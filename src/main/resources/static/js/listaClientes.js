function eliminar(id){
  Swal.fire({
      title: '¿Estás seguro de eliminar este registro?',
      text: "¡No se podrá revertir esta acción!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#3085d6',
      cancelButtonColor: '#d33',
      confirmButtonText: '¡Sí, eliminar!'
    }).then((OK) => {
      if (OK) {
          $.ajax({
              url:"/listaClientes/"+id,
              success: function(res){
                  console.log(res);
              }
          })
        Swal.fire(
          '¡Registro eliminado!',
          'El registro ha sido eliminado.',
          'success'
        )
      }
    }).then((ok) => {
      if(ok) {
        location.reload();
      }
    })
  }