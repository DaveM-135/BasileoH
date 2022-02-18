$(document).ready(function() {
	
//	var rangeIsFrom = "";
//	var rangeIsTo = "";
//	var semanaActual = new Date().getFullYear() + '-W' +getWeekNr();
//	document.getElementById("semana").defaultValue=semanaActual;
	
	$("#proyecto").change(function(){
		$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
//		var sem = document.getElementById("semana").value.substring(6); 
		var url = "/listadoRecursos/"+proyectoSeleccion(this.value);
		$("#recursosHoras").load(url);
	});
	
//	$("#semana").change(function(){
//		$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
//		var pro = document.getElementById("proyecto").value; 
//		var url = getDateRangeOfWeek(this.value.substring(6))+"/"+proyectoSeleccion(pro);
//		$("#recursosHoras").load(url);
//	});
	
	datosInicial();
	
//	$("span.captura").dblclick(function(){
//		alert($(this).innerHTML);
//	});
	
});


function esRechazada(est) {
    var personRegExp = new RegExp('danger');
    if (personRegExp.test(est)) {
        return 1;
    } else {
        return 0;
    }
}

function esPendiente(est) {
    var personRegExp = new RegExp('warning');
    if (personRegExp.test(est)) {
        return 1;
    } else {
        return 0;
    }
}

function datosInicial(){
//	document.getElementById("semana").disabled = false;
	document.getElementById("proyecto").disabled = false;
	$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
	var pro = document.getElementById("proyecto").value; 
//	var sem = document.getElementById("semana").value.substring(6); 
//	var url = getDateRangeOfWeek(sem) +"/"+proyectoSeleccion(pro);
	var url = "/listadoRecursos/" + proyectoSeleccion(pro);
	$("#recursosHoras").load(url);
}

function aprobarSolicitud(cod){
	$("#aprSol_"+cod).html('<i class="spinner-border spinner-border-sm"></i>')
	$("#recSol_"+cod).hide();
	var aprobador = $("#authGetName").val();
	$.ajax({
	    type: "GET",
	    url: "/updAprobacionSolicitud",
	    data: {codSolicitud: cod, 
	    		aprobador: aprobador},
		success: function(result){
	        if(result == 'ok'){
//	        	$("#aprSol_"+cod).html('<span>Aprobada <i class="far fa-check-circle"></i></span>');
	        	$("#estat_"+cod).html('<span class="badge badge-success">Aprobada <i class="far fa-check-circle"></i></span>');
	        	$("#aprSol_"+cod).hide();
//	        	$("#recSol_"+cod).show();
	        	$("#opcs_"+cod).html('<a  id="canSol_'+ cod + '" onclick="cancelarSolicitud('+ cod + '); return false;" href="#" class="badge badge-danger">Cancelar  <i class="far fa-times-circle"></i></a>');
	        } else {
	        	alert("Hubo un problema al actualizar el registro, intente nuevamente.");
	        }
			
	    }
	});
}

function rechazarSolicitud(cod){
	$("#recSol_"+cod).html('<i class="spinner-border spinner-border-sm"></i>')
	$("#aprSol_"+cod).hide();
	var aprobador = $("#authGetName").val();
	$.ajax({
	    type: "GET",
	    url: "/updRechazoSolicitud",
	    data: {codSolicitud: cod, 
	    		aprobador: aprobador},
		success: function(result){
	        if(result == 'ok'){
//	        	$("#aprSol_"+cod).html('<span>Aprobada <i class="far fa-check-circle"></i></span>');
	        	$("#estat_"+cod).html('<span class="badge badge-danger">Rechazada <i class="far fa-times-circle"></i></span>');
	        	$("#recSol_"+cod).hide();
//	        	$("#aprSol_"+cod).show();
	        } else {
	        	alert("Hubo un problema al actualizar el registro, intente nuevamente.");
	        }
			
	    }
	});
}

function cancelarSolicitud(cod){
	$("#canSol_"+cod).html('<i class="spinner-border spinner-border-sm"></i>')
//	$("#aprSol_"+cod).hide();
	var aprobador = $("#authGetName").val();
	$.ajax({
	    type: "GET",
	    url: "/updCancelarSolicitud",
	    data: {codSolicitud: cod, 
	    		aprobador: aprobador},
		success: function(result){
	        if(result == 'ok'){
//	        	$("#aprSol_"+cod).html('<span>Aprobada <i class="far fa-check-circle"></i></span>');
	        	$("#estat_"+cod).html('<span class="badge badge-danger">Cancelada <i class="far fa-times-circle"></i></span>');
	        	$("#canSol_"+cod).hide();
//	        	$("#aprSol_"+cod).show();
	        } else {
	        	alert("Hubo un problema al actualizar el registro, intente nuevamente.");
	        }
			
	    }
	});
}


function detalleVacaciones(codRecurso){
//	document.getElementById("semana").disabled = true;
	document.getElementById("proyecto").disabled = true;
	
	$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');

	var url = "/aprobacionVacaciones/detalle/?r="+codRecurso;
//	$("#recursosHoras").load(url, function(){
//		totales();
//    });
	$("#recursosHoras").load(url);
	
}

function proyectoSeleccion(val){
	if (val == '-1'){
		return codProyecto();
	} else {
		return val;
	}
}

//obtiene listado de todos los proyectos;
function codProyecto(){
	var codProyectos="";
	$("#proyecto option").each(function(){
		codProyectos = codProyectos + $(this).val() + ",";
	});
	return codProyectos;
}

//Obtiene el numero de la semana actual de inicio
function getWeekNr() {
	var now = new Date(), i = 0, f, sem = (new Date(now.getFullYear(), 0, 1) .getDay() > 0) ? 1 : 0;
	while ((f = new Date(now.getFullYear(), 0, ++i)) < now) {
		if (!f.getDay()) {
			sem++;
		}
	}
	return sem;
}

//Obtiene el numero de la semana seleccionado en la vista
function semanaSeleccion(obj){//2020-W38
	var WeekNo = obj.value.substring(6); 
	getDateRangeOfWeek(WeekNo);
}

//Obtiene rango de fechas de la semana del parametro
function getDateRangeOfWeek(weekNo){
    var d1 = new Date();
    numOfdaysPastSinceLastMonday = eval(d1.getDay()- 1);
    d1.setDate(d1.getDate() - numOfdaysPastSinceLastMonday);
    var weekNoToday = getWeekNr();
    var weeksInTheFuture = eval( weekNo - weekNoToday );
    d1.setDate(d1.getDate() + eval( 7 * weeksInTheFuture ));
    rangeIsFrom = eval(d1.getMonth()+1) +"-" + d1.getDate() + "-" + d1.getFullYear();
//    var from = rangeIsFrom.split("-")[2] + "-" + (rangeIsFrom.split("-")[0])-1 + "-" + rangeIsFrom.split("-")[1];
    d1.setDate(d1.getDate() + 6);
    rangeIsTo = eval(d1.getMonth()+1) +"-" + d1.getDate() + "-" + d1.getFullYear() ;
//    var to = rangeIsTo.split("-")[2] + "-" + (rangeIsTo.split("-")[0])-1 + "-" + rangeIsTo.split("-")[1];
 
//    return rangeIsFrom + " to "+rangeIsTo;
    
    var url="/capturaHorasPeriodo/"+rangeIsFrom +"/"+rangeIsTo;
    return url;
//    console.log(url);
//	$("#recursosHoras").load(url);
};


	