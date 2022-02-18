$(document).ready(function() {
	verExpedientes($("#codRecurso").val());

});

function cargarArchivo(cod){
	var url = "/formDocumento/?r="+$("#codRecurso").val()+"&d="+cod
	$("#recursoExpedienteDigitalModal").load(url, function(){
		$("#registroExpedienteModal").modal('show');
	});
}

function editarArchivo(cod){
	var url = "/formEditDocumento/?r="+$("#codRecurso").val()+"&d="+cod
	$("#recursoExpedienteDigitalModal").load(url, function(){
		$("#registroExpedienteModal").modal('show');
	});
}

function submitFormExpediente(){
	var $form_expediente = $('#formularioExpedienteDigital')[0];
	var data = new FormData($form_expediente);
	if ($("#documentoExpediente").val() != ""){
	    $.ajax({
	        type: "POST",
	        enctype: 'multipart/form-data',
	        url: '/formDocumento',
	        data: data,
	        processData: false,
	        contentType: false,
	        cache: false,
	        timeout: 1000000,
	        success: function(data) {
	            $("#registroExpedienteModal").modal('hide');
	            verExpedientes($("#codRecurso").val());
	        }
	    });
	} else {
		alert("Selecciona un archivo");
	}
	
	
 
}

function verExpedientes(codRecurso){
	var url = "/verExpedientesRecurso/?r=" + codRecurso;
	$("#expediente-digital").load(url);
}


function validarArchivo(cod){
	 $.ajax({
		    type: "GET",
		    url: "/aprobarDocumento",
		    data: {r:$("#codRecurso").val(),
		    	d: cod.substring(4)},
			success: function(result){
				 verExpedientes($("#codRecurso").val());
		    }
		});	
	
}

function rechazarArchivo(cod){
	 $.ajax({
		    type: "GET",
		    url: "/rechazarDocumento",
		    data: {r:$("#codRecurso").val(),
		    	d: cod.substring(4)},
			success: function(result){
				 verExpedientes($("#codRecurso").val());
		    }
		});	
	
}