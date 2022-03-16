when RULE_INIT {
    set static::maxRate 3
    set static::windowSecs 1 
}
 
when HTTP_REQUEST {
    if { ([HTTP::method] eq "GET") and ([class match [string tolower [HTTP::uri]] starts_with DATAGROUP-RATELIMIT-URI] ) } {
 
        # whitelist
        if { [class match [IP::client_addr] equals DATAGROUP-RATELIMIT-WHITELIST] }{
           return
        }
 
        # set variables
        set limiter [string tolower [HTTP::uri]]
        set clientip_limitervar [IP::client_addr]:$limiter
        set get_count [table key -count -subtable $clientip_limitervar]
 
        # main condition
        if { $get_count < $static::maxRate } {
            incr get_count 1
             table set -subtable $clientip_limitervar $get_count $clientip_limitervar indefinite $static::windowSecs
        } else {
            log local0. "$clientip_limitervar has exceeded the number of requests allowed."
            drop
            return
        }
    }
}
