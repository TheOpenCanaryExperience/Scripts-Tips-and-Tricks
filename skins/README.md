# Skinning the OpenCanary HTTP interface
Location: ~/env/lib/python3.10/site-packages/opencanary/modules/data/http/skin/basicLogin (typical)
File: index.html (other files unlikely to work)

Note: Remove this section if you do not want to ramp up a direct connection to port x that you're running to go through a reverse proxy for TLS.  This allows a configuration without TLS configured in OpenCanary (avoiding copying pem files and so on) but then routing traffic via Caddy or similar.
<script>
        // Redirect to the desired URL with HTTPS - for example if you redirect to HTTPS through a reverse proxy.  If you don't, you can remove this script section
        if (window.location.href !== 'https://your_reverse_proxy/index.html') {
            // Redirect to the desired URL
            window.location.href = 'https://your_reverse_proxy/index.html';
        }
</script>

