$(document).ready(function() {
	
	misEvaluados($("#authGetName").val());

});

function misEvaluados(sesion){
	jsShowWindowLoad();
	var url = "/verMisEvaluados/?s="+sesion;
	$("#divListaMisEvaluados").load(url, function(){
		jsRemoveWindowLoad();
	});
	
}

function verDetalleCompetenciasEvaluador(id){
	jsShowWindowLoad();
	var codEvaluacion = id.split("-")[0];
	var codRecurso = id.split("-")[1];
	var codEvaluador = id.split("-")[2];
	url="/getRespuestasEvaluacionEvaluador/?re="+ codRecurso + "&ev=" + codEvaluacion + "&er="+ codEvaluador;
	$("#divModalDetalleRespuestas").load(url, function(){
		$("#modalDetalleRespuestas").modal("toggle");
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



