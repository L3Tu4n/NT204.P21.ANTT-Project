@load base/frameworks/notice
@load base/utils/time
@ifndef(Site::darknet_mode)
@load packages/bro-is-darknet
@endif

module Scan;

export {
    #Phân loại Notice
    redef enum Notice::Type += {
        Address_Scan,
        Port_Scan,
        Random_Scan,
    };
    #Attempt lưu thông tin về một lần thử quét, gồm địa chỉ nạn nhân (victim) và cổng bị quét (scanned_port).
    type Attempt: record {
        victim: addr;
        scanned_port: port;
    };
    #Scan_Info lưu thông tin chi tiết về hoạt động quét của một máy quét.
    type Scan_Info: record {
        first_seen: time;
        attempts: set[Attempt];
        port_counts: table[port] of count;
        dark_hosts: set[addr];
    };
    #Thiết lập các các ngưỡng để xác định đang bị scan
    const scan_timeout = 15min &redef;
    const dark_host_threshold = 3 &redef;
    const scan_threshold = 25 &redef;
    const local_scan_threshold = 250 &redef;
    const scan_threshold_with_darknet_hits = 10 &redef;
    const local_scan_threshold_with_darknet_hits = 100 &redef;
    const knockknock_threshold = 20 &redef;
    const knockknock_threshold_with_darknet_hits = 3  &redef;

    global Scan::scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);

    #scan_attempt: event nội bộ báo khi có một attempt mới vượt qua policy.    
    global scan_attempt: event(scanner: addr, attempt: Attempt);
 
    #Các bảng toàn cục 
    #attacks: lưu Scan_Info cho mỗi địa chỉ scanner, tự động xóa sau scan_timeout     
    global attacks: table[addr] of Scan_Info &read_expire=scan_timeout &redef;
    
    #recent_scan_attempts: ngăn duplicate attempts trong vòng 1 phút (giúp giảm noise).    
    global recent_scan_attempts: table[addr] of set[Attempt] &create_expire=1mins;
    
    #known_scanners: Lưu danh sách các máy quét đã biết, hết hạn sau 10 giây, với hàm điều chỉnh thời gian hết hạn adjust_known_scanner_expiration
    global adjust_known_scanner_expiration: function(s: table[addr] of interval, idx: addr): interval;
    
    global known_scanners: table[addr] of interval &create_expire=10secs &expire_func=adjust_known_scanner_expiration;
}

    #Khi notice được tạo ra thì thêm scanner vào known_scanners để tạm thời không phân tích thêm attempt của nó tránh spam notice.
event Notice::begin_suppression(ts: time, suppress_for: interval, note: Notice::Type, identifier: string)
{
    if (note == Address_Scan || note == Random_Scan || note == Port_Scan)
    {
        local src = to_addr(identifier);
        known_scanners[src] = suppress_for;
        delete recent_scan_attempts[src];
    }
}
    #Điều chỉnh thời gian hết hạn cho các máy quét đã biết
function adjust_known_scanner_expiration(s: table[addr] of interval, idx: addr): interval
{
    local duration = s[idx];
    s[idx] = 0secs;
    return duration;
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() != Cluster::WORKER )
#Phân tích kiểu scan và tạo notice 
function analyze_unique_hostports(attempts: set[Attempt]): Notice::Info
{
    local ports: set[port];
    local victims: set[addr];

    local ports_str: set[string];
    local victims_str: set[string];

    for ( a in attempts )
    {
        add victims[a$victim];
        add ports[a$scanned_port];
        add victims_str[cat(a$victim)];
        add ports_str[cat(a$scanned_port)];
    }

    if(|ports| == 1)
    {
        for (p in ports)
        {
            return [$note=Address_Scan, $msg=fmt("%s unique hosts on port %s", |victims|, p), $p=p];
        }
    }

    if(|victims| == 1)
    {
        for (v in victims)
            return [$note=Port_Scan, $msg=fmt("%s unique ports on host %s", |ports|, v)];
    }

    if(|ports| <= 5)
    {
        local ports_string = join_string_set(ports_str, ", ");
        return [$note=Address_Scan, $msg=fmt("%s unique hosts on ports %s", |victims|, ports_string)];
    }

    if(|victims| <= 5)
    {
        local victims_string = join_string_set(victims_str, ", ");
        return [$note=Port_Scan, $msg=fmt("%s unique ports on hosts %s", |ports|, victims_string)];
    }

    return [$note=Random_Scan, $msg=fmt("%d hosts on %d ports", |victims|, |ports|)];
}
#Tạo notice dựa trên thông tin quét
function generate_notice(scanner: addr, si: Scan_Info): Notice::Info
{
    local side = Site::is_local_addr(scanner) ? "local" : "remote";
    local dur = duration_to_mins_secs(network_time() - si$first_seen);
    local n = analyze_unique_hostports(si$attempts);
    n$msg = fmt("%s scanned at least %s in %s", scanner, n$msg, dur);
    n$src = scanner;
    n$sub = side;
    n$identifier=cat(scanner);
    return n;
}
#chịu trách nhiệm thu thập và đánh giá từng “attempt” (lần thử) quét từ một IP scanner, rồi quyết định xem đã đến lúc phát hiện (NOTICE)
function add_scan_attempt(scanner: addr, attempt: Attempt)
{
    if ( scanner in known_scanners )
        return;

    local si: Scan_Info;
    local attempts: set[Attempt];
    local dark_hosts: set[addr];
    local port_counts: table[port] of count;

    if ( scanner !in attacks)
    {
        attempts = set();
        port_counts = table();
        dark_hosts = set();
        si = Scan_Info($first_seen=network_time(), $attempts=attempts, $port_counts=port_counts, $dark_hosts=dark_hosts);
        attacks[scanner] = si;
    }
    else
    {
        si = attacks[scanner];
        attempts = si$attempts;
        port_counts = si$port_counts;
        dark_hosts = si$dark_hosts;
    }

    if ( attempt in attempts )
        return;

    add attempts[attempt];
    if (attempt$scanned_port !in port_counts)
        port_counts[attempt$scanned_port] = 1;
    else
        ++port_counts[attempt$scanned_port];

    if(|dark_hosts| < dark_host_threshold && attempt$victim !in dark_hosts && Site::is_darknet(attempt$victim)) {
        add dark_hosts[attempt$victim];
    }

    local thresh: count;
    local is_local = Site::is_local_addr(scanner);

    local is_darknet_scan = |dark_hosts| >= dark_host_threshold;

    if ( is_darknet_scan )
        thresh = is_local ? local_scan_threshold_with_darknet_hits : scan_threshold_with_darknet_hits;
    else
        thresh = is_local ? local_scan_threshold : scan_threshold;

    local is_scan = |attempts| >= thresh;
    local is_knockkock = F;
    if ( !is_local )
    {
        local knock_thresh = is_darknet_scan ? knockknock_threshold_with_darknet_hits : knockknock_threshold;
        is_knockkock = port_counts[attempt$scanned_port] >= knock_thresh;
    }

    if ( is_scan || is_knockkock)
    {
        local note = generate_notice(scanner, si);
        if ( is_knockkock )
            note$msg = fmt("kk: %s", note$msg);
        NOTICE(note);
        delete attacks[scanner];
        known_scanners[scanner] = 1hrs;
    }
}
@endif

@if ( Cluster::is_enabled() )
@ifdef (Cluster::worker2manager_events)
redef Cluster::worker2manager_events += /Scan::scan_attempt/;
@endif

function add_scan(id: conn_id)
{
    local scanner      = id$orig_h;
    local victim       = id$resp_h;
    local scanned_port = id$resp_p;

    if ( scanner in known_scanners )
        return;

    if ( hook Scan::scan_policy(scanner, victim, scanned_port) )
    {
        local attempt = Attempt($victim=victim, $scanned_port=scanned_port);
        if ( scanner !in recent_scan_attempts)
            recent_scan_attempts[scanner] = set();
        if ( attempt in recent_scan_attempts[scanner] )
            return;
        add recent_scan_attempts[scanner][attempt];
@ifdef (Cluster::worker2manager_events)
        event Scan::scan_attempt(scanner, attempt);
@else
        Cluster::publish_hrw(Cluster::proxy_pool, scanner, Scan::scan_attempt, scanner, attempt);
@endif
    }
}
@endif