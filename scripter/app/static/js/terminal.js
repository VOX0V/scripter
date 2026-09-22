(function () {
    var page = document.querySelector(".terminal-page");
    if (!page || typeof io !== "function") {
        return;
    }

    var csrfToken = page.getAttribute("data-csrf-token");
    var forms = document.querySelectorAll(".terminal-input-form");
    var executionIds = Array.prototype.slice.call(forms)
        .map(function (form) {
            return parseInt(form.getAttribute("data-execution-id"), 10);
        })
        .filter(function (id) {
            return Number.isInteger(id) && id > 0;
        });

    if (!csrfToken || executionIds.length === 0) {
        return;
    }

    var socket = io();

    socket.on("connect", function () {
        executionIds.forEach(function (id) {
            socket.emit("join", { execution_id: id, csrf: csrfToken });
        });
    });

    socket.on("output", function (msg) {
        var el = document.getElementById("output-" + msg.id);
        if (el) {
            el.textContent += msg.data;
            el.scrollTop = el.scrollHeight;
        }
    });

    socket.on("status", function (msg) {
        var badge = document.getElementById("status-" + msg.id);
        if (badge) {
            var label = "En cours";
            if (msg.status === "success") {
                label = "Terminé";
            } else if (msg.status === "error") {
                label = "Erreur";
            } else if (msg.status === "timeout") {
                label = "Timeout";
            }
            badge.textContent = label;
            badge.className = "badge " + msg.status;
        }
    });

    forms.forEach(function (form) {
        form.addEventListener("submit", function (evt) {
            evt.preventDefault();
            var id = parseInt(form.getAttribute("data-execution-id"), 10);
            var input = document.getElementById("input-" + id);
            if (!input || !Number.isInteger(id) || id <= 0) {
                return;
            }
            socket.emit("terminal_input", {
                execution_id: id,
                text: input.value + "\n",
                csrf: csrfToken
            });
            input.value = "";
        });
    });
})();
