$ORIGIN .
$TTL 300	; 5 minutes
ccdrew.cc		IN SOA	cc.alt.org. drew.alt.org. (
				2021022831 ; serial
				3600       ; refresh (1 hour)
				900        ; retry (15 minutes)
				604800     ; expire (1 week)
				86400      ; minimum (1 day)
				)
			NS	cc.alt.org.
			A	52.45.246.197
$ORIGIN ccdrew.cc.
*			A	52.45.246.197
