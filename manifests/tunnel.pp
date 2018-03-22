# ex: si ts=4 sw=4 et

define shorewall::tunnel (
    $proto   = 'ipv4',
    $gateway = '0.0.0.0/0',
    $type,
    $zone,
) {
    case $proto {
        'ipv4': {
            if $shorewall::ipv4_tunnels {
                concat::fragment { "tunnel-ipv4-${type}-${gateway}":
                    order   => '50',
                    target  => '/etc/shorewall/tunnels',
                    content => "${type} ${zone} ${gateway}\n",
                }
            } else {
                fail('An ipv4 tunnel has been defined but \'ipv4_tunnels\' is false')
            }
        }
        'ipv6': {
            if $shorewall::ipv6_tunnels {
                concat::fragment { "tunnel-ipv6-${type}-${gateway}":
                    order   => '50',
                    target  => '/etc/shorewall6/tunnels',
                    content => "${type} ${zone} ${gateway}\n",
                }
            } else {
                fail('An ipv6 tunnel has been defined been \'ipv6_tunnels\' is false')
            }
        }
        default: { fail("Unknown value for 'proto': ${proto}") }
    }
}
