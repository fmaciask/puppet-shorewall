# ex: si ts=4 sw=4 et

define shorewall::rule (
    $application   = '',
#    Optional[Array] $source,
    Variant[Undef,String,Array]  $source,
    $dest,
    $action,
#    $application   = 'ACCEPT',
    $proto         = 'tcp',
    $port          = '',
    $sport         = '',
    $original_dest = '',
    $ipv4          = $::shorewall::ipv4,
    $ipv6          = $::shorewall::ipv6,
    $order         = '50',
) {
    if $application == '' {
    #    validate_re($proto, '^(([0-9]+|tcp|udp|icmp|-)(?:,|$))+')
        validate_legacy(String, 'validate_re', $proto, '^(([0-9]+|tcp|udp|icmp|-)(?:,|$))+')
    #    validate_re($port, ['^:?[0-9]+:?$', '^-$', '^[0-9]+[:,][0-9]+$'])
        validate_legacy(String, 'validate_re',$port, ['^:?[0-9]+:?$', '^-$', '^[0-9]+[:,][0-9]+$'])
    #    validate_legacy(Array, 'validate_array', $source)
    } else {
    #    validate_re($application, '^[[:alnum:]]+$')
        validate_legacy(String, 'validate_re', $application, '^[[:alnum:]]+$')
    #    validate_re($proto, '^-?$')
        validate_legacy(String, 'validate_re', $proto, '^-?$')
    #    validate_re($port, '^-?$')
        validate_legacy(String, 'validate_re', $port, '^-?$')
    }
    if $original_dest != '' {
    #    validate_re($sport, '[^\s]+')
        validate_legacy(String, 'validate_re', $port, '[^\s]+')
    }

    if $ipv4 {
#         concat::fragment { "rule-ipv4-${name}":
#             order   => $order,
#             target  => '/etc/shorewall/rules',
#             content => template('shorewall/rule.erb'),
#         }
#      $source.each |$fuente| {
        concat::fragment { "rule-ipv4-${name}":
            order   => $order,
            target  => '/etc/shorewall/rules',
            content => template('shorewall/rule.erb'),
        }
#      }
   }

    if $ipv6 {
        concat::fragment { "rule-ipv6-${name}":
            order   => $order,
            target  => '/etc/shorewall6/rules',
            content => template('shorewall/rule.erb'),
        }
    }
}
