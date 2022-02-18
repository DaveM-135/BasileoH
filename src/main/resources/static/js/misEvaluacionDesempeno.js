$(document).ready(function() {
	jsShowWindowLoad();
	misEvaluaciones($("#authGetName").val());

});

function misEvaluaciones(sesion){
	var url = "/verMisEvaluaciones/?s="+sesion;
	$("#divListaMisEvaluaciones").load(url, function(){
		jsRemoveWindowLoad();
	});
}

function verDetalleMetas(id){
	jsShowWindowLoad();
	var codEvaluacion = id.split("-")[0];
	var codRecurso = id.split("-")[1];
	url="/getRespuestasMetas/?re="+ codRecurso + "&ev=" + codEvaluacion;
	$("#divModalDetalleMetas").load(url, function(){
		$("#modalDetalleMetas").modal("toggle");
		jsRemoveWindowLoad();
	});
}

function verDetalleCompetencias(id){
	jsShowWindowLoad();
	var codEvaluacion = id.split("-")[0];
	var codRecurso = id.split("-")[1];
	url="/getRespuestasEvaluacion/?re="+ codRecurso + "&ev=" + codEvaluacion;
	$("#divModalDetalleRespuestas").load(url, function(){
		$("#modalDetalleRespuestas").modal("toggle");
		jsRemoveWindowLoad();
	});
}

function verDetalleCompetenciasEvaluado(id){
	jsShowWindowLoad();
	var codEvaluacion = id.split("-")[0];
	var codRecurso = id.split("-")[1];
	url="/getRespuestasEvaluacionEvaluado/?re="+ codRecurso + "&ev=" + codEvaluacion;
	$("#divModalDetalleRespuestas").load(url, function(){
		$("#modalDetalleRespuestas").modal("toggle");
		jsRemoveWindowLoad();
	});
}

function verDetalleEvaluacion(cod){
	var url = "/verDetalleEvaluacion/?e="+cod;
	$("#divDetalleEvaluacion").load(url, function (){
		$("#modalDetalleEvaluacion").modal('toggle');
	});
}

function nuevaEvaluacion(){
	var url="/nuevaEvaluacion";
	$("#divNuevaEvaluacion").load(url, function (){
		$("#tablaCandidatos").hide();
		$("#validacionNombre").hide();
		$("#validacionInicioPeriodo").hide();
		$("#validacionFinPeriodo").hide();
		$("#modalNuevaEvaluacion").modal('toggle');
	});
}

function guardarEvaluacion(){
	var nombre = $("#descEvaluacionDesempeno").val();
	var pInicio = $("#fecPeriodoInicio").val();
	var pFin = $("#fecPeriodoFin").val();
	var err= 0;
	
	if(nombre.length == 0){
		err++;
		$("#validacionNombre").show();
	} else {
		$("#validacionNombre").hide();
	}
	
	if(pInicio.length == 0){
		err++;
		$("#validacionInicioPeriodo").show();
	} else {
		$("#validacionInicioPeriodo").hide();
	}
	
	if(pFin.length == 0){
		err++;
		$("#validacionFinPeriodo").show();
	} else {
		$("#validacionFinPeriodo").hide();
	}
	
	if($("#inicioEvaluacion").prop('checked')) {
		if($(".chkRecurso:checked").length == 0){
			err++;
			alert("No hay recursos seleccionados");
		}
	}
	
	if (err == 0){
		if($("#inicioEvaluacion").prop('checked')) {
			if (confirm('\xbfDeseas iniciar el periodo de evaluación?\nValida nuevamente la selección de recursos.\nEsta tarea no se podrá revertir.')) {
				$("#formularioEvaluacion").submit();
			}
		} else {
			$("#formularioEvaluacion").submit();
		}
		
	}
}

function editarEvaluacion(cod){
	var url = "/editarDetalleEvaluacion/?e="+cod;
	$("#divNuevaEvaluacion").load(url, function (){
		$("#tablaCandidatos").hide();
		$("#validacionNombre").hide();
		$("#validacionInicioPeriodo").hide();
		$("#validacionFinPeriodo").hide();
		$("#modalNuevaEvaluacion").modal('toggle');
	});
}

function borrarEvaluacion(cod){
	if (confirm('\xbfDeseas borrar la evaluación?')) {
		$.ajax({
		    url: '/borrarEvaluacion',
		    type: 'GET',
		    data: { e: cod} ,
		    success: function(result) {
	        	location.reload();
	          }
		}); 
		}
}

