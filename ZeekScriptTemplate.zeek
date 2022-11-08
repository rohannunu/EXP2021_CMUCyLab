##Based on Seth Hall YouTube Tutorial: Introduction to Zeek Script Writing

module insertDeviceName;

export{
    redef enum Log::ID += { insertDeviceName::LOG };
    const allowed: table[subnet] of set[subnet] = { [insert host address] = set(insert destination IPs) } &redef;

    type Info: record {
        ts: time &log;
        orighost: addr &log;
        strangeIP: addr &log;
        strangePort: port &log;
    };

}

event zeek init(){
    Log::create_stream(LOG, [$columns=Info]);
}

event connection_established(c: connection)
{
    if ( c$id$resp_h !in allowed){
        Log::write(LOG, Info($ts=network_time(),
                             $orighost=c$id$orig_h,
                             $strangeIP=c$id$resp_h,
                             $strangePort=c$id$resp_p));
    }
}

