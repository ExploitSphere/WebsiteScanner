async function scanWebsite() {

    const urlInput = document.getElementById("url");
    const url = urlInput.value.trim().replace(/\s+/g, "");

    if (url === "") {
        alert("Please Enter Website URL");
        return;
    }

    document.getElementById("loading").style.display = "block";
    document.getElementById("result").style.display = "none";
    document.getElementById("portResult").style.display = "none";

    try {

        const response = await fetch("http://localhost:5000/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        const data = await response.json();

        document.getElementById("loading").style.display = "none";

        if (!data.success) {
            alert(data.message);
            return;
        }

        const result = data.website;
        const portResult = data.ports;

        document.getElementById("result").style.display = "grid";

        // ================= WEBSITE INFORMATION =================

        document.getElementById("status").innerHTML =
            result.reachable ? "✅ Reachable" : "❌ Not Reachable";

        document.getElementById("status_code").innerHTML =
            result.status_code;

        document.getElementById("response_time").innerHTML =
            result.response_time + " sec";

        document.getElementById("https").innerHTML =
            result.https ? "✅ Enabled" : "❌ Disabled";

        // ================= DNS =================

        document.getElementById("domain").innerHTML =
            result.domain;

        document.getElementById("ip").innerHTML =
            result.ip_address;

        // ================= SERVER =================

        document.getElementById("server").innerHTML =
            result.server;

        // ================= SECURITY SCORE =================

        document.getElementById("score").innerHTML =
            result.security_score;

        // ================= HEADERS FOUND =================

        let found = "";

        result.headers_found.forEach(function(header){

            found += "<li>✅ " + header + "</li>";

        });

        document.getElementById("headers_found").innerHTML = found;

        // ================= HEADERS MISSING =================

        let missing = "";

        result.headers_missing.forEach(function(header){

            missing += "<li>❌ " + header + "</li>";

        });

        document.getElementById("headers_missing").innerHTML = missing;

        // ================= ROBOTS =================

        document.getElementById("robots").innerHTML =
            result.robots ? "✅ Found" : "❌ Not Found";

        if(result.robots){

            document.getElementById("robots_link").style.display = "inline-block";
            document.getElementById("robots_link").href = result.robots_url;

        }
        else{

            document.getElementById("robots_link").style.display = "none";

        }

        // ================= SITEMAP =================

        document.getElementById("sitemap").innerHTML =
            result.sitemap ? "✅ Found" : "❌ Not Found";

        if(result.sitemap){

            document.getElementById("sitemap_link").style.display = "inline-block";
            document.getElementById("sitemap_link").href = result.sitemap_url;

        }
        else{

            document.getElementById("sitemap_link").style.display = "none";

        }

        // ================= REDIRECT =================

        let redirectHTML = "";

        if(result.redirects.length === 0){

            redirectHTML = "<li>No Redirect Found</li>";

        }
        else{

            result.redirects.forEach(function(r){

                const cleanUrl = (r.url || "").replace(/\s+/g, "");

                redirectHTML += `
                    <li>
                        ${r.status_code} → ${cleanUrl}
                    </li>
                `;

            });

        }

        document.getElementById("redirects").innerHTML = redirectHTML;

        // ================= WHOIS =================

        document.getElementById("registrar").innerHTML =
            result.whois.registrar || "N/A";

        document.getElementById("created").innerHTML =
            result.whois.creation_date || "N/A";

        document.getElementById("expiry").innerHTML =
            result.whois.expiration_date || "N/A";

        // ================= SSL =================

        document.getElementById("ssl").innerHTML =
            result.ssl.available ? "✅ Available" : "❌ Not Available";

        document.getElementById("ssl_expiry").innerHTML =
            result.ssl.expiry || "N/A";

        // ================= COOKIES =================

        let cookieHTML = "";

        if (result.cookies.length === 0) {

            cookieHTML = "<li>No Cookies Found</li>";

        } else {

            result.cookies.forEach(function (cookie) {

                cookieHTML += `
                    <li>
                        <b>${cookie.name}</b><br>
                        Secure : ${cookie.secure ? "✅" : "❌"}<br>
                        HttpOnly : ${cookie.httponly ? "✅" : "❌"}
                    </li><br>
                `;

            });

        }

        document.getElementById("cookies").innerHTML = cookieHTML;

        // ================= PORT SCANNER =================

        document.getElementById("portResult").style.display = "block";

        const cleanTarget = (portResult.target || "").replace(/\s+/g, "");
        const cleanIp = (portResult.ip || "").replace(/\s+/g, "");

        document.getElementById("scan_target").innerHTML = cleanTarget;

        document.getElementById("scan_ip").innerHTML = cleanIp;

        document.getElementById("open_ports").innerHTML =
            portResult.open_ports;

        document.getElementById("ports_checked").innerHTML =
            portResult.ports_checked;

        document.getElementById("scan_time").innerHTML =
            portResult.scan_time + " sec";

        // ================= PORT CARDS =================

        let cards = "";

        portResult.ports.forEach(function(port){

            let statusClass =
                port.status === "Open"
                ? "status-open"
                : "status-closed";

            let risk = "-";
            let riskClass = "";

            portResult.risk_analysis.forEach(function(r){

                if(r.port === port.port){

                    risk = r.risk;

                    if(risk.startsWith("Low")){

                        riskClass = "risk-low";

                    }
                    else if(risk.startsWith("Medium")){

                        riskClass = "risk-medium";

                    }
                    else{

                        riskClass = "risk-high";

                    }

                }

            });

            cards += `

            <div class="port-card">

                <h3>${port.service} (${port.port})</h3>

                <p>
                    <strong>Status :</strong>
                    <span class="${statusClass}">
                        ${port.status}
                    </span>
                </p>

                <p>
                    <strong>Risk :</strong>
                    <span class="${riskClass}">
                        ${risk}
                    </span>
                </p>

            </div>

            `;

        });

        document.getElementById("portCards").innerHTML = cards;

    }

    catch(error){

        document.getElementById("loading").style.display = "none";

        alert("Something Went Wrong");

        console.log(error);

    }
}

// ================= ENTER KEY SUPPORT =================

function handleEnter(event){

    if(event.key === "Enter"){

        event.preventDefault();

        scanWebsite();

    }

}