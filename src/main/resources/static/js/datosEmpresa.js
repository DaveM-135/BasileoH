$(document).ready(function() {

	$('.js-example-basic-multiple').select2();
	
	resetFormHerramienta();
	
	$("#iNuevaHerramienta").click(function(){
	 	$("#nuevaHerramientaModal").show();
	 	resetFormHerramienta();
	 });
	 
	 if($("#valActivo").val() == 1){
	 		$("#fecSalida").hide();
	 		$("#motivo").hide();
	 	} else {
	 		$("#fecSalida").show();
	 		$("#motivo").show();
	 	}
	 
	 $("#valActivo").click(function(){
	 	if($(this).val() == 1){
	 		$("#fecSalida").hide();
	 		$("#motivo").hide();
	 	} else {
	 		$("#fecSalida").show();
	 		$("#motivo").show();
	 	}
	 });
	 
});

function resetFormHerramienta(){
	$("#codHerramientaRecurso").val("");
	$("#observaciones").val("");
	//$("#responsiva").val("");
	$("#fecPrestamo").val("");
	$("#fecDevolucion").val("");
	$("#validObservaciones").hide();
	$("#validResponsiva").hide();
	$("#validCodHerramienta").hide();
	$("#validCodTipoHerramienta").hide();
}




function submitFormHerramientas(){
	var $form_herramientas = $('#formularioHerramientas')[0];
	var data = new FormData($form_herramientas);
//	$("#btnAceptarCapacitacion").prop("disabled", true);
	
    $.ajax({
        type: "POST",
        enctype: 'multipart/form-data',
        url: '/formCrearEditarHerramienta',
        data: data,
        processData: false,
        contentType: false,
        cache: false,
        timeout: 1000000,
        success: function(data) {
//            $("#btnAceptarCapacitacion").prop("disabled", false);
        	var url = "/obtieneHerramienta/?codRecurso="+$("#codRecurso").val();
			$("#divHerramientas").load(url);
            $("#registroHerramientaModal").modal('hide');
//            verTrayectoriaCapacitacion($("#codRecurso").val());
        }
    });
}

function abrirFormHerramienta(){
	var url = "/formCrearEditarHerramienta/?codRecurso=" + $("#codRecurso").val();
	$("#recursoHerramientaModal").load(url,function(){
		$("#registroHerramientaModal").modal('show');
	});
}
  
function editarHerramienta(codHerramientaRecurso){
	var url = "/formEditarHerramienta/?chr=" + codHerramientaRecurso;
	$("#recursoHerramientaModal").load(url,function(){
		$("#registroHerramientaModal").modal('show');
	});
}
  

function borrarHerramienta(codHerramienta){
	var codRecurso = $("#codRecurso").val();
	$.ajax({
		type: "GET",
		url: "/borrarHerramienta",
		data: {ch: codHerramienta },
		success: function(result){
			var url = "/obtieneHerramienta/?codRecurso="+codRecurso;
			$("#divHerramientas").load(url);
	    }
	});
}
