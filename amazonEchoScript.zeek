##Based on Seth Hall YouTube Tutorial: Introduction to Zeek Script Writing

module amazonEcho;

export{
    redef enum Log::ID += { amazonEcho::LOG };
    const allowed: table[subnet] of set[subnet] = { [192.168.1.240/32] = set(224.0.0.22/32, 239.255.255.250/32, 255.255.255.255/32, 208.67.220.220/32, 224.0.0.251/32) } &redef;

    type Info: record {
        ts: time &log;
        orighost: addr &log;
        strangeIP: addr &log;
        strangePort: port &log;
    };

}

event zeek_init(){
    Log::create_stream(LOG, [$columns=Info]);
}

event connection_established(c: connection)
{
    if ( c$id$orig_h in allowed) {

        if ( c$id$resp_h !in allowed[c$id$orig_h]){
            Log::write(LOG, Info($ts=network_time(),
                                 $orighost=c$id$orig_h,
                                 $strangeIP=c$id$resp_h,
                                 $strangePort=c$id$resp_p));
        }
    }
}

