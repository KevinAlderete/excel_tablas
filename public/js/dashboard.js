// Función para mostrar el modal de error con SweetAlert2
function showErrorModal(message) {
  Swal.fire({
    title: "Error",
    text: message,
    icon: "error",
    confirmButtonText: "Cerrar",
  });
}
// Función para cerrar sesión
document.getElementById("logoutButton").addEventListener("click", () => {
  localStorage.removeItem("token"); // Elimina el token
  window.location.href = "/"; // Redirige al login
});

// Obtener los datos de la API y actualizar la tabla
async function fetchData() {
  // Mostrar el loader
  const loader = document.getElementById("loader");
  loader.classList.remove("hidden");
  try {
    const response = await fetch("/data");
    const { hoja, datos } = await response.json();

    // Mostrar el nombre de la hoja
    document.getElementById(
      "hojaNombre"
    ).textContent = `Datos de la hoja: ${hoja}`;

    if (!datos || datos.length === 0) {
      console.warn("No hay datos disponibles para mostrar.");
      document.getElementById("tableBody").innerHTML =
        "<tr><td colspan='100%'>No hay datos disponibles</td></tr>";
      return;
    }

    // Configurar encabezados dinámicos
    const headers = datos[0]; // Primera fila como encabezados
    const headerRow = headers.map((header) => `<th>${header}</th>`).join("");
    document.getElementById("tableHeader").innerHTML = headerRow;

    // Configurar cuerpo de la tabla
    const tableBody = datos
      .slice(1) // Excluir la primera fila si son encabezados
      .map((row) => {
        const cells = row.map((cell) => `<td>${cell || ""}</td>`).join("");
        return `<tr>${cells}</tr>`;
      })
      .join("");
    document.getElementById("tableBody").innerHTML = tableBody;

    // // **Generar Reporte de Estados**
    // const stateCounts = {};
    // const stateColumnIndex = 11; // Ajustar según la posición de la columna

    // datos.slice(1).forEach((row) => {
    //   const estado = row[stateColumnIndex];
    //   if (estado) {
    //     stateCounts[estado] = (stateCounts[estado] || 0) + 1;
    //   }
    // });

    // // Crear el contenido del reporte
    // const reportBody = document.getElementById("reportBody");

    // document.getElementById("showReport").addEventListener("click", () => {
    //   reportBody.innerHTML = ""; // Limpiar reporte previo
    //   Object.entries(stateCounts).forEach(([estado, cantidad]) => {
    //     const row = `<tr>
    //          <td>${estado}</td>
    //          <td>${cantidad}</td>
    //        </tr>`;
    //     reportBody.innerHTML += row;
    //   });
    // });

    // Verificar si DataTable ya está inicializado
    const tableElement = $("#example");
    if ($.fn.DataTable.isDataTable(tableElement)) {
      tableElement.DataTable().destroy(); // Destruir DataTable existente
    }

    // Inicializar DataTables con SearchPanes
    tableElement.DataTable({
      paging: true, // Activar paginación
      searching: true, // Activar búsqueda
      ordering: false, // Desactivar ordenamiento
      scrollX: true, // Habilitar scroll horizontal
      info: true,
      //autoWidth: false, // Deshabilitar ajuste automático de ancho de columna
      dom: "Bfrtip", // Activar SearchPanes (P) y configurar el layout
      //dom: "Plfrtip", // Activar SearchPanes (P) y configurar el layout
      buttons: [
        {
          extend: "excelHtml5",
          text: "Exportar a Excel",
          className: "btn btn-success", // Clase Bootstrap para estilos
          exportOptions: {
            columns: ":visible", // Exportar solo columnas visibles
          },
          customize: function (xlsx) {
            // Personalizar el archivo generado
            const sheet = xlsx.xl.worksheets["sheet1.xml"];

            // Define colores en las celdas según su estado
            $("row", sheet).each(function () {
              const celdas = $(this).find("c");
              celdas.each(function () {
                const cellValue = $(this).text();

                // Aplica colores basados en el estado
                if (cellValue === "APROBADO") {
                  $(this).attr("s", "40"); // Estilo de celda 10 (verde)
                } else if (cellValue === "NO INICIA") {
                  $(this).attr("s", "30"); // Estilo de celda 20 (rojo)
                } else if (cellValue === "EN PROCESO") {
                  $(this).attr("s", "20"); // Estilo de celda 30 (amarillo)
                } else if (cellValue === "DESAPROBADO") {
                  $(this).attr("s", "10"); // Estilo de celda 40 (gris)
                }
              });
            });
          },
        },
        {
          extend: "pdfHtml5",
          text: "Exportar a PDF",
          className: "btn btn-danger",
          orientation: "landscape", // Orientación horizontal
          pageSize: "A4", // Tamaño de página
          exportOptions: {
            columns: ":visible",
          },
        },
        {
          extend: "csvHtml5",
          text: "Exportar a CSV",
          className: "btn btn-primary",
          exportOptions: {
            columns: ":visible",
          },
        },
        {
          extend: "print",
          text: "Imprimir",
          className: "btn btn-secondary",
          exportOptions: {
            columns: ":visible",
          },
        },
        {
          extend: "colvis",
          text: "Mostrar/Ocultar Columnas",
          className: "btn btn-info",
          postfixButtons: ["colvisRestore"],
        },
      ],
      language: {
        processing: "Cargando datos...", // Mensaje para el indicador de carga
        search: "Buscar:", // Etiqueta del cuadro de búsqueda
        lengthMenu: "Mostrar _MENU_ entradas",
        info: "Mostrando _START_ a _END_ de _TOTAL_ entradas",
        infoEmpty: "No hay datos disponibles",
        infoFiltered: "(filtrado de _MAX_ entradas totales)",
        paginate: {
          first: "Primero",
          last: "Último",
          next: "Siguiente",
          previous: "Anterior",
        },
      },
      createdRow: function (row, data, dataIndex) {
        // Supongamos que el estado está en la columna índice 12
        const estado = data[11]; // Usamos una columna de referencia para obtener el estado

        let classColor = "";
        if (estado === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        }

        $("td", row).eq(11).addClass(classColor);

        const estado2 = data[12]; // Usamos una columna de referencia para obtener el estado2

        if (estado2 === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado2 === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado2 === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado2 === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        }

        $("td", row).eq(12).addClass(classColor);

        const estado3 = data[13]; // Usamos una columna de referencia para obtener el estado3

        if (estado3 === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado3 === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado3 === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado3 === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        }

        $("td", row).eq(13).addClass(classColor);

        const estado4 = data[14]; // Usamos una columna de referencia para obtener el estado4

        if (estado4 === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado4 === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado4 === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado4 === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        }

        $("td", row).eq(14).addClass(classColor);

        const estado5 = data[15]; // Usamos una columna de referencia para obtener el estado5

        if (estado5 === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado5 === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado5 === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado5 === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        }

        $("td", row).eq(15).addClass(classColor);

        const estado6 = data[16]; // Usamos una columna de referencia para obtener el estado6

        if (estado6 === "APROBADO") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado6 === "NO INICIA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        } else if (estado6 === "EN PROCESO") {
          classColor = "bg-warning-subtle text-warning fw-bold";
        } else if (estado6 === "DESAPROBADO") {
          classColor = "bg-secondary-subtle text-secondary fw-bold";
        } else if (estado6 === "APROBADO EL PROGRAMA") {
          classColor = "bg-success-subtle text-success fw-bold";
        } else if (estado6 === "DESAPROBÓ EL PROGRAMA") {
          classColor = "bg-danger-subtle text-danger fw-bold";
        }

        $("td", row).eq(16).addClass(classColor);
      },
    });
    // Ocultar el loader
    loader.classList.add("hidden");
  } catch (error) {
    console.error("Error al cargar datos:", error);
  }
}

// Llamar a la función al cargar la página
document.addEventListener("DOMContentLoaded", fetchData);
