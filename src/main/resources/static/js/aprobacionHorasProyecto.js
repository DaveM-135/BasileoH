$(document).ready(function() {
	var rangeIsFrom = "";
	var rangeIsTo = "";
	var from = "";
	var to = "";
	var semanaActual = new Date().getFullYear() + '-W' +getWeekNr(new Date().toISOString().substring(0,10));
	document.getElementById("semana").defaultValue=semanaActual;
	
	$("#proyecto").change(function(){
		$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
		var sem = document.getElementById("semana").value.substring(6);
		var ano = document.getElementById("semana").value.substring(0,4);
		var url = getDateRangeOfWeek(sem, ano)+"/"+proyectoSeleccion(this.value);
		$("#recursosHoras").load(url);
	});
	
	$("#semana").change(function(){
		$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
		var pro = document.getElementById("proyecto").value; 
		var url = getDateRangeOfWeek(this.value.substring(6), this.value.substring(0,4))+"/"+proyectoSeleccion(pro);
		$("#recursosHoras").load(url);
	});
	
	datosInicial();
	
	$("span.captura").dblclick(function(){
		alert($(this).innerHTML);
	});
	
});

function totales(){
	var total_lun = 0;
	var total_mar = 0;
	var total_mie = 0;
	var total_jue = 0;
	var total_vie = 0;
	var total_sab = 0;
	var total_dom = 0;
	var total_lunR = 0;
	var total_marR = 0;
	var total_mieR = 0;
	var total_jueR = 0;
	var total_vieR = 0;
	var total_sabR = 0;
	var total_domR = 0;
	var total_lunP = 0;
	var total_marP = 0;
	var total_mieP = 0;
	var total_jueP = 0;
	var total_vieP = 0;
	var total_sabP = 0;
	var total_domP = 0;
	
	var totalSemana = 0;
	var totalSemanaR = 0;
	var totalSemanaP = 0;
	
	$('#dataTableDetalle tbody').find('tr').each(function (i, el) {
		est = $(this).find('td').eq(0).find('div').html();
		if (esRechazada(est)){
			total_lunR += parseFloat($(this).find('td').eq(1).text());
			total_marR += parseFloat($(this).find('td').eq(2).text());
			total_mieR += parseFloat($(this).find('td').eq(3).text());
			total_jueR += parseFloat($(this).find('td').eq(4).text());
			total_vieR += parseFloat($(this).find('td').eq(5).text());
			total_sabR += parseFloat($(this).find('td').eq(6).text());
			total_domR += parseFloat($(this).find('td').eq(7).text());
		} else if (esPendiente(est)) {
			total_lunP += parseFloat($(this).find('td').eq(1).text());
			total_marP += parseFloat($(this).find('td').eq(2).text());
			total_mieP += parseFloat($(this).find('td').eq(3).text());
			total_jueP += parseFloat($(this).find('td').eq(4).text());
			total_vieP += parseFloat($(this).find('td').eq(5).text());
			total_sabP += parseFloat($(this).find('td').eq(6).text());
			total_domP += parseFloat($(this).find('td').eq(7).text());
			} else {
				total_lun += parseFloat($(this).find('td').eq(1).text());
				total_mar += parseFloat($(this).find('td').eq(2).text());
				total_mie += parseFloat($(this).find('td').eq(3).text());
				total_jue += parseFloat($(this).find('td').eq(4).text());
				total_vie += parseFloat($(this).find('td').eq(5).text());
				total_sab += parseFloat($(this).find('td').eq(6).text());
				total_dom += parseFloat($(this).find('td').eq(7).text());
			}
	});
	
	$("#dia1").text((isNaN(total_lun) ? '0': total_lun) + ' hrs')
	$("#dia2").text((isNaN(total_mar) ? '0': total_mar) + ' hrs')
	$("#dia3").text((isNaN(total_mie) ? '0': total_mie) + ' hrs')
	$("#dia4").text((isNaN(total_jue) ? '0': total_jue) + ' hrs')
	$("#dia5").text((isNaN(total_vie) ? '0': total_vie) + ' hrs')
	$("#dia6").text((isNaN(total_sab) ? '0': total_sab) + ' hrs')
	$("#dia7").text((isNaN(total_dom) ? '0': total_dom) + ' hrs')
	
	totalSemana = total_lun + total_mar + total_mie + total_jue + total_vie + total_sab + total_dom;
	totalSemanaR = total_lunR + total_marR + total_mieR + total_jueR + total_vieR + total_sabR + total_domR;
	totalSemanaP = total_lunP + total_marP + total_mieP + total_jueP + total_vieP + total_sabP + total_domP;
	
	$("#totalSemana").text('('+ (isNaN(totalSemana) ? '0': totalSemana) + ' hrs aprobadas, ' + (isNaN(totalSemanaR) ? '0': totalSemanaR)  + ' hrs rechazadas, ' + (isNaN(totalSemanaP) ? '0': totalSemanaP)  + ' hrs pendientes)');
	
}


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
	document.getElementById("semana").disabled = false;
	document.getElementById("proyecto").disabled = false;
	$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
	var pro = document.getElementById("proyecto").value; 
	var sem = document.getElementById("semana").value.substring(6); 
	var ano = document.getElementById("semana").value.substring(0,4);
	var url = getDateRangeOfWeek(sem, ano) +"/"+proyectoSeleccion(pro);
	$("#recursosHoras").load(url);
}

function aprobar(cod){
	$("#aprA"+cod).html('<i class="spinner-border spinner-border-sm"></i>')
	$("#aprR"+cod).hide();
	var hrAprobada = $("#apr"+cod).text();
	var aprobador = $("#authGetName").val();
	$.ajax({
	    type: "GET",
	    url: "/updAprobacion",
	    data: {codCapHora: cod, 
	    		hrAprobada:hrAprobada,
	    		aprobador: aprobador},
		success: function(result){
	        if(result == 'ok'){
	        	$("#aprA"+cod).html('Aprobada <i class="far fa-check-circle"></i>');
	        	$("#est"+cod).html('<span class="badge badge-success"><i class="far fa-check-circle"></i></span>');
	        	$("#aprR"+cod).show();
	        	totales();
	        } else {
	        	alert("Hubo un problema al actualizar el registro, intente nuevamente.");
	        }
			
	    }
	});
	
}

function rechazar(cod){
	var coment = prompt("Detalle del rechazo:");
	if (coment != null && coment != "") {
		$("#aprR"+cod).html('<i class="spinner-border spinner-border-sm"></i>')
		$("#aprA"+cod).hide();
		var aprobador = $("#authGetName").val();
		$.ajax({
		    type: "GET",
		    url: "/updRechazar",
		    data: {codCapHora: cod, 
		    		aprobador: aprobador,
		    		comentario: coment},
			success: function(result){
		        if(result == 'ok'){
		        	$("#aprR"+cod).html('Rechazado <i class="far fa-times-circle"></i>');
		        	$("#aprA"+cod).show();
		        	$("#est"+cod).html('<span class="badge badge-danger"><i class="far fa-times-circle"></i></span>');
		        	totales();
		        } else {
		        	alert("Hubo un problema al actualizar el registro, intente nuevamente.");
		        }
				
		    }
		});	
		 
	} else {
		alert("Sin detalle, no se puede rechazar.");
	}
	
	
	
}


function detalleCaptura(obj){
	document.getElementById("semana").disabled = true;
	document.getElementById("proyecto").disabled = true;
	$("#recursosHoras").html('<div class="spinner-grow text-muted"></div>');
	var codRecurso = $(obj).attr('id');
	var codPr = document.getElementById("proyecto").value; 
	var semana = document.getElementById("semana").value;
	var proyectos="";
	
	if (codPr == '-1'){
		proyectos = codProyecto();
	} else {
		proyectos = codPr;
	}

	var url = "/aprobacionHorasProyecto/detalle/?r="+codRecurso+"&p="+proyectos+"&s="+semana+"&f="+from+"&t="+to;
	$("#recursosHoras").load(url, function(){
		totales();
    });
	
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
function getWeekNr(fecha) {
	if(fecha.match(/\//)){
      fecha   =   fecha.replace(/\//g,"-",fecha); //Permite que se puedan ingresar formatos de fecha ustilizando el "/" o "-" como separador
   };
   
   fecha   =   fecha.split("-"); //Dividimos el string de fecha en trozos (dia,mes,año)
   ano   =   eval(fecha[0]);
   mes   =   eval(fecha[1]);
   dia   =   eval(fecha[2]);
   
   if (mes==1 || mes==2){
      //Cálculos si el mes es Enero o Febrero
      a   =   ano-1;
      b   =   Math.floor(a/4)-Math.floor(a/100)+Math.floor(a/400);
      c   =   Math.floor((a-1)/4)-Math.floor((a-1)/100)+Math.floor((a-1)/400);
      s   =   b-c;
      e   =   0;
      f   =   dia-1+(31*(mes-1));
   } else {
      //Calculos para los meses entre marzo y Diciembre
      a   =   ano;
      b   =   Math.floor(a/4)-Math.floor(a/100)+Math.floor(a/400);
      c   =   Math.floor((a-1)/4)-Math.floor((a-1)/100)+Math.floor((a-1)/400);
      s   =   b-c;
      e   =   s+1;
      f   =   dia+Math.floor(((153*(mes-3))+2)/5)+58+s;
   };

   //Adicionalmente sumándole 1 a la variable $f se obtiene numero ordinal del dia de la fecha ingresada con referencia al año actual.

   //Estos cálculos se aplican a cualquier mes
   g   =   (a+b)%7;
   d   =   (f+g-e)%7; //Adicionalmente esta variable nos indica el dia de la semana 0=Lunes, ... , 6=Domingo.
   n   =   f+3-d;
   
   if (n<0){
      //Si la variable n es menor a 0 se trata de una semana perteneciente al año anterior
      semana   =   53-Math.floor((g-s)/5);
      ano      =   ano-1; 
   } else if (n>(364+s)) {
      //Si n es mayor a 364 + $s entonces la fecha corresponde a la primera semana del año siguiente.
      semana   = 1;
      ano   =   ano+1;
   } else {
      //En cualquier otro caso es una semana del año actual.
      semana   =   Math.floor(n/7)+1;
   };
   
   if(semana < 10){
   		semana = '0'+semana;
   }
   
   return semana;
   //return $semana+"-"+$ano; La función retorna una cadena de texto indicando la semana y el año correspondiente a la fecha ingresada
}

//Obtiene el numero de la semana seleccionado en la vista
function semanaSeleccion(obj){//2020-W38
	var WeekNo = obj.value.substring(6);
	var year = obj.value.substring(0,4);
	getDateRangeOfWeek(WeekNo, year);
}

function getDateOfISOWeek(weekNo, year) {
    var simple = new Date(year, 0, 1 + (weekNo - 1) * 7);
    var dow = simple.getDay();
    var ISOweekStart = simple;
    if (dow <= 4){
        ISOweekStart.setDate(simple.getDate() - simple.getDay() + 1);
    }
    else{
        ISOweekStart.setDate(simple.getDate() + 8 - simple.getDay());
    }
    return ISOweekStart;
}

//Obtiene rango de fechas de la semana del parametro
function getDateRangeOfWeek(weekNo, year){
	var date = getDateOfISOWeek(weekNo, year);
    //var rangeIsFromISO = date.toISOString().slice(0, 10);
    rangeIsFrom = date;
    from = eval(rangeIsFrom.getMonth() + 1) + '-' + rangeIsFrom.getDate() + '-' + rangeIsFrom.getFullYear();
    date.setDate(date.getDate() + 6);
    //var rangeIsToISO = date.toISOString().slice(0, 10);
    rangeIsTo = date;
    to = eval(rangeIsTo.getMonth() + 1) + '-' + rangeIsTo.getDate() + '-' + rangeIsTo.getFullYear() ;
    
    var url="/capturaHorasPeriodo/"+from +"/"+to;
    return url;
}