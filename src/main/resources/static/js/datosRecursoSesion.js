$(document).ready(function() {
	$('#btnFlash').hide();
	
	var url="/datosRecursoLogin/"+$("#authGetName").val();
	$("#encabezado").load(url);
	
	validaFlash();
	
	var url="/datosOpcionesRecursoLogin/"+$("#authGetName").val();
	$("#opciones").load(url);
	

});

function validaFlash(){
	$.ajax({
		url: '/validaRespuestaFlash',
		data: { recurso: $("#authGetName").val()},
		success: function(succ){
			if(succ == '1'){
				muestraFlash();
				$('#btnFlash').show();
			}
		}
	})
}

function muestraFlash(){
	var urlFlash="/datosRecursoLoginFlash/"+$("#authGetName").val();
	$("#suveyFlashSophi").load(urlFlash, function(){
		flashSurvey();
	});
}

function flashSurvey(){
	$('#modalClima').modal('show'); 
}

function saveRespuesta(objRespuesta){
	var resp = $(objRespuesta).attr("id").substring(4);
	var codPregunta = $(pregunta).val();
	$.ajax({
		url: '/guardaRespuestaFlash',
		data: { recurso: $("#authGetName").val(), 
				respuesta: resp,
				pregunta: codPregunta},
		success: function(succ){
			$('#modalClima').modal('hide');
			$('#btnFlash').hide();
		}
	})
}