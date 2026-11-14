function showBanner(data) {
  if (document.getElementById("scamshield-banner")) return;
  const bar = document.createElement("div");
  bar.id = "scamshield-banner";
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;" +
    "background:#d6336c;color:#fff;padding:14px 18px;" +
    "font:16px Arial,sans-serif;text-align:center;" +
    "box-shadow:0 2px 8px rgba(0,0,0,.4);";
  bar.textContent =
    "ScamShield warning: this page looks dangerous. " +
    "Do not enter passwords, OTPs or payment details. ";
  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.style.cssText = "margin-left:12px;padding:4px 10px;cursor:pointer;";
  close.onclick = () => bar.remove();
  bar.appendChild(close);
  document.body.prepend(bar);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SHOW_WARNING") showBanner(msg.data);
});