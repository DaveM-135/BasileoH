$(document).ready(function() {

});

function registrarCapacitacion(){
	console.log("entra");
	var url = "/formCapacitaciones";
	$("#divCapacitacionesModal").load(url, function(){
		$("#registroCapacitacionesModal").modal('show');
	});
}


function editarCapacitacion(cod){
	var url = "/editarCapacitaciones/?c="+cod;
	$("#divCapacitacionesModal").load(url, function(){
		$("#registroCapacitacionesModal").modal('show');
	});
}


function eliminarCapacitacion(cod){
	$.ajax({
		type: "GET",
		url:"/eliminarCapacitacion",
		data:{c:cod},
		success: function(res){
			if(res == "1"){
				location.reload();
			} else {
				alert("Problema al eliminar el registro");
			}
		}
	})
}
