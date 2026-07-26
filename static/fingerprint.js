function getCanvasFingerprint() {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");

    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillText("Fingerprint Test", 2, 2);

    return canvas.toDataURL();
}

function collectFingerprint() {
    return {
        canvas: getCanvasFingerprint(),
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        referrer: document.referrer || "direct visit"
    };
}

window.addEventListener("load", async () => {
    const fingerprint = collectFingerprint();

    try {
        const response = await fetch("/collect", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(fingerprint)
        });

        const result = await response.json();
        console.log(result);
    } catch (err) {
        console.error("Failed to send fingerprint:", err);
    }
});