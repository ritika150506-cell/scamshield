async function run() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  document.getElementById("url").textContent = tab.url;
  const v = document.getElementById("verdict");
  const list = document.getElementById("reasons");

  if (!tab.url.startsWith("http")) {
    v.textContent = "Not a web page";
    return;
  }
  try {
    const res = await fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await res.json();
    v.textContent = data.verdict;
    v.className = data.verdict;
    list.innerHTML = "";
    data.reasons.forEach(r => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });
  } catch (e) {
    v.textContent = "API not running";
  }
}
run();