# configure mikrotik calea

```code
/ip firewall calea
remove [find]  ;# falls du alte Regeln hast, erstmal bereinigen

/ip firewall address-list
add list=nocalea address=10.5.0.0/19 comment="keine internen Systeme spiegeln"

/ip firewall calea
add action=sniff chain=forward in-interface=telekom-pppoe \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=bridge1 \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan1   \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan2   \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan3   \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan4   \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan5   \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"

add action=sniff chain=forward in-interface=vlan10  \
    sniff-target=10.5.1.60 sniff-target-port=37008 \
    src-address-list=!nocalea comment="Mirror für Security Onion"



```

