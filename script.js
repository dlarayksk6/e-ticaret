const API_URL = "http://localhost:5000";


document.getElementById("registerForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const kullaniciadi = document.getElementById("registerUsername").value;
    const sifre = document.getElementById("registerPassword").value;

    const response = await fetch(`${API_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kullaniciadi, sifre }),
    });

    const data = await response.json();
    alert(data.message);
});


document.getElementById("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const kullaniciadi = document.getElementById("loginUsername").value;
    const sifre = document.getElementById("loginPassword").value;

    const response = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kullaniciadi, sifre }),
    });

    const data = await response.json();

    if (data.token) {
        localStorage.setItem("token", data.token);
        alert("Giriş başarılı!");
    } else {
        alert("Hata: " + data.message);
    }
});


document.getElementById("protectedButton").addEventListener("click", async () => {
    const token = localStorage.getItem("token");

    if (!token) {
        alert("Önce giriş yapmalısınız!");
        return;
    }

    const response = await fetch(`${API_URL}/protected`, {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` }

    });

    const data = await response.json();
    document.getElementById("protectedData").innerText = JSON.stringify(data);
});
