document.addEventListener("DOMContentLoaded", function () {
    const botonesVerMensaje = document.querySelectorAll(".ver-mensaje");

    botonesVerMensaje.forEach(boton => {
        boton.addEventListener("click", function () {
            const idMensaje = boton.dataset.id;

            // Simulación de datos para ejemplo
            const datosMensaje = {
                nombre_galleta: "Chocolate Chip",
                cantidad_galleta: "25"
            };

            // Asignar datos al modal de mensaje
            document.getElementById("nombre-galleta").innerText = datosMensaje.nombre_galleta;
            document.getElementById("cantidad-galleta").innerText = datosMensaje.cantidad_galleta;
            document.getElementById("id-mensaje").value = idMensaje;

            // Cerrar el modal de notificaciones si estaba abierto
            const modalNotificaciones = bootstrap.Modal.getInstance(document.getElementById("modalNotificaciones"));
            if (modalNotificaciones) {
                modalNotificaciones.hide();
            }

            // Abrir el modal de mensaje
            const modalMensaje = new bootstrap.Modal(document.getElementById("modalMensaje"));
            modalMensaje.show();
        });
    });
});
