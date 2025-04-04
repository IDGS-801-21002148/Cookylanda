document.addEventListener('DOMContentLoaded', function() {
    // Agregar nuevo ingrediente
    document.getElementById('agregar-ingrediente').addEventListener('click', function() {
      const container = document.getElementById('ingredientes-adicionales');
      const newIndex = container.querySelectorAll('.ingredient-row').length;
      
      const newRow = document.createElement('div');
      newRow.className = 'row ingredient-row mb-3';
      newRow.innerHTML = `
        <div class="col-md-4">
          <input type="text" class="form-control" name="adicional[]" placeholder="Nombre" required>
        </div>
        <div class="col-md-3">
          <input type="text" class="form-control" name="cantAdicional[]" placeholder="Cantidad" required>
        </div>
        <div class="col-md-3">
          <select name="unidad[]" class="form-select" required>
            <option value="Gramos">Gramos</option>
            <option value="Mililitros">Mililitros</option>
            <option value="Litros">Litros</option>
            <option value="Kilos">Kilos</option>
            <option value="Unidades">Unidades</option>
            <option value="Tazas">Tazas</option>
          </select>
        </div>
        <div class="col-md-2 d-flex align-items-center">
          <button type="button" class="btn btn-delete eliminar-ingrediente">
            <i class="bi bi-trash"></i>
          </button>
        </div>
      `;
      
      container.appendChild(newRow);
    });

    // Eliminar ingrediente
    document.getElementById('ingredientes-adicionales').addEventListener('click', function(e) {
      if (e.target.closest('.eliminar-ingrediente')) {
        const rows = document.querySelectorAll('.ingredient-row');
        if (rows.length > 1) {
          e.target.closest('.ingredient-row').remove();
        } else {
          Swal.fire({
            title: 'Atención',
            text: 'Debe haber al menos un ingrediente adicional',
            icon: 'warning'
          });
        }
      }
    });

    // Validación del formulario
    document.querySelector('form').addEventListener('submit', function(e) {
      let isValid = true;
      
      // Validar campos vacíos
      document.querySelectorAll('input[required], select[required]').forEach(input => {
        if (!input.value.trim()) {
          input.classList.add('is-invalid');
          isValid = false;
        } else {
          input.classList.remove('is-invalid');
        }
      });
      
      // Validar cantidades numéricas
      document.querySelectorAll('input[name="cantAdicional[]"]').forEach(input => {
        if (isNaN(input.value) || input.value.trim() === '') {
          input.classList.add('is-invalid');
          isValid = false;
        }
      });
      
      if (!isValid) {
        e.preventDefault();
        Swal.fire({
          title: 'Error',
          text: 'Por favor complete todos los campos correctamente',
          icon: 'error'
        });
      }
    });
  });