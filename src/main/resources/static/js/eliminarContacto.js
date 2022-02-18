function eliminar(id) {
	$("#codigoContacto").val(id);
	$("#eliminarRegistro").modal("show");
}

function eliminarRegistro(){
	$.ajax({
		type: "GET",
		url:"/agenda/"+$("#codigoContacto").val(),
		success: function(res){
			console.log(res);
			if(res == "1"){
				location.reload();
			}
			$("#eliminarRegistro").modal("hide");
		}
	})
}