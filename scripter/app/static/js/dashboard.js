(function () {
    var preview = document.getElementById("script-preview");
    var recapScript = document.getElementById("recap-script");
    var recapTargets = document.getElementById("recap-targets");

    if (!preview || !recapScript || !recapTargets) {
        return;
    }

    document.querySelectorAll(".script-radio").forEach(function (radio) {
        radio.addEventListener("change", function () {
            var content = radio.getAttribute("data-content");

            try {
                content = JSON.parse(content);
            } catch (e) {
                content = "(contenu introuvable)";
            }

            preview.textContent = content || "(contenu introuvable)";
            recapScript.textContent = radio.value.split("::").join(" / ");
        });
    });

    function updateTargets() {
        var checked = Array.prototype.slice.call(
            document.querySelectorAll(".server-checkbox:checked")
        );

        if (checked.length === 0) {
            recapTargets.textContent = "aucune";
        } else {
            recapTargets.textContent = checked
                .map(function (c) {
                    return c.getAttribute("data-label");
                })
                .join(", ");
        }
    }

    document.querySelectorAll(".server-checkbox").forEach(function (cb) {
        cb.addEventListener("change", updateTargets);
    });
})();
