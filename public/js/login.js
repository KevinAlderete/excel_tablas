document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const userId = document.getElementById("userId").value;
  const password = document.getElementById("password").value;

  // Mostrar el loader
  const loader = document.getElementById("loader");
  loader.classList.remove("hidden");

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId, password }),
    });

    const result = await response.json();

    if (response.ok) {
      //alert("Login exitoso");
      localStorage.setItem("token", result.token); // Guardar el token
      window.location.href = "/dashboard"; // Redirigir a la página de datos
    } else {
      //alert(result.error);
      showErrorModal(
        result.error || "Ocurrió un error, por favor intenta nuevamente."
      );
    }
  } catch (error) {
    alert("Ocurrió un error, por favor intenta nuevamente.");
    console.error("Error:", error);
    showErrorModal("Ocurrió un error, por favor intenta nuevamente.");
  } finally {
    // Ocultar el loader
    loader.classList.add("hidden");
  }
});

// Función para mostrar el modal de error con SweetAlert2
function showErrorModal(message) {
  Swal.fire({
    title: "Error",
    text: message,
    icon: "error",
    confirmButtonText: "Cerrar",
  });
}
