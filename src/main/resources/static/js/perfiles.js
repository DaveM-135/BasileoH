$(document).ready(function() {
	

});

function verMetasyCompetencias(cod){
	jsShowWindowLoad();
	var url = "/getMetasCompetencias/?c="+cod;
	$("#divMetasCompetencias").load(url, function(){
		$("#modalMetasCompetencias").modal('toggle');
		jsRemoveWindowLoad();
	});
}


function editarP(n){
	var url = "/editarPerfil/?c="+n;
	$("#divPerfil").load(url, function(){
		$("#modalPerfil").modal('toggle');
		obtenerMetasEditar(n);
		obtenerCompetenciasEditar(n);
		$("#validacionDescripcion").hide();
		$("#validacionFunciones").hide();
		$("#validacionObjetivo").hide();
		$("#validacionSeleccionCompetencias").hide();
		$("#validacionSeleccionMetas").hide();
		$("#totalMetas").html("100%");
	});
}

function nuevoPerfil(){
	var url = "/formPerfil";
	$("#divPerfil").load(url, function(){
		$("#modalPerfil").modal('toggle');
		$("#validacionDescripcion").hide();
		$("#validacionFunciones").hide();
		$("#validacionObjetivo").hide();
		$("#validacionSeleccionCompetencias").hide();
		$("#validacionSeleccionMetas").hide();
	});
}

function obtenerMetasEditar(n){
	$.ajax({
        url: '/getMetasEditar',
        type: 'GET',
        data:{c:n},
        success: function(response) {
        	 $("#tableMetas tbody").append(response);
          }
    });
}

function obtenerCompetenciasEditar(n){
	$.ajax({
        url: '/getCompetenciasEditar',
        type: 'GET',
        data:{c:n},
        success: function(response) {
        	 $("#tableCompetencias tbody").append(response);
          }
    });
}

function enviarFormPerfil(){
	jsShowWindowLoad();
	var descripcion = $("#descPerfil").val();
	var funciones = $("#descFunciones").val();
	var objetivo = $("#descObjetivo").val();
	var totalMetasAsignadas = $("input[name='porcentajeMeta[]']").length;
	var totalCompetenciasAsignadas = $("textarea[name='reactivoCompetencia[]']").length;
	var validacion = 0;
	
	if(descripcion.length == 0){
		 $("#validacionDescripcion").show();
		 validacion++;
	} else {
		 $("#validacionDescripcion").hide();
	}
	
	if(objetivo.length == 0){
		 $("#validacionObjetivo").show();
		 validacion++;
	} else {
		 $("#validacionObjetivo").hide();
	}
	
	if(funciones.length == 0){
		 $("#validacionFunciones").show();
		 validacion++;
	} else {
		$("#validacionFunciones").hide();
	}
	
	if (totalMetasAsignadas == 0){
		$("#validacionSeleccionMetas").show();
		validacion++;
	} else {
		$("#validacionSeleccionMetas").hide();
	}
	
	if (totalCompetenciasAsignadas == 0){
		validacion++;
		$("#validacionSeleccionCompetencias").show();
	} else {
		var valReact = 0;
		$("textarea[name='reactivoCompetencia[]']").each(function() {
			if (this.value.length == 0){
				validacion++;
				valReact++;
			} 
		});
		if(valReact == 0){
			$("#validacionSeleccionCompetencias").hide();
		} else {
			$("#validacionSeleccionCompetencias").show();
		}
	}
	
	if ($("#totalMetas").html() != "100%"){
		$("#validacionSeleccionMetas").show();
		validacion++;
	} else {
		$("#validacionSeleccionMetas").hide();
	}
	
	if(validacion == 0){
		document.getElementById("formularioPerfil").submit();
	}
}


//COMPETENCIAS
function asignarCompetencia(){
	var url = "/getCompetencias";
	$("#divCompetencias").load(url, function(){
		$("#divSeleccionCompetencia").show();
		$("#divCreacionCompetencia").hide();
		$("#btnActuaDefinicionCompetencia").hide();
		$("#modalCompetencias").modal('toggle');
		$("#valNSC").val("1");
	});
}


function nuevaCompetencia(){
	$("#divSeleccionCompetencia").hide();
	$("#divCreacionCompetencia").show();
	$("#valNSC").val("2");
	$("#validacionNomCom").hide();
	$("#validacionDefCom").hide();
}

function seleccionarCompetencia(){
	$("#divSeleccionCompetencia").show();
	$("#divCreacionCompetencia").hide();
	$("#valNSC").val("1");
}

function obtenerDefinicion(competencia){
	$("#definicionCompetencia").prop('readonly', true);
	$("#btnEditDefinicionCompetencia").show();
	$("#btnActuaDefinicionCompetencia").hide();
	$.ajax({
        url: '/getDefinicionCompetencia',
        type: 'GET',
        data:{c:competencia},
        success: function(response) {
        	$("#definicionCompetencia").val(response);
          }
    });
}

function borrarCompetencia(e){
	$(e).parents("tr").remove();
}

function guardarCompetencia(){
	var bandera = $("#valNSC").val();
	var nombreCompetencia = "";
	var DefCompetencia = "";
	var validacion = 0;
	
	if(bandera == "1"){
		nombreCompetencia = $("#selectCompetencia option:selected").text();
		DefCompetencia = $("#definicionCompetencia").val();
	} else if (bandera == "2"){
		
		var nomCom = $("#inputCreacionCompetencia").val();
		var defC = $("#inputDefCreacionCompetencia").val();
		
		if(nomCom.length == 0 ){
			$("#validacionNomCom").show();
		 	validacion++;
		} else {
			$("#validacionNomCom").hide();
			nombreCompetencia = $("#inputCreacionCompetencia").val();
		}

		if(defC.length == 0){
			$("#validacionDefCom").show();
			validacion++;
		} else {
			$("#validacionDefCom").hide();
			DefCompetencia = $("#inputDefCreacionCompetencia").val();
		}
		
	}
	
	if(validacion == 0){
	    var markup = "<tr>" +
			    "<td class='d-none'><input type='hidden' value='"+ bandera+"' name='banderaCompetencia[]'</td>" +
				"<td class='d-none'><input type='hidden' value='"+ nombreCompetencia+"' name='nombreCompetencia[]'</td>" +
				"<td class='d-none'><input type='hidden' value='"+ DefCompetencia+"' name='definicionCompetencia[]'</td>" +	
	    		"<td style='vertical-align: middle; font-size: 12px; padding: 5px;'>" + nombreCompetencia + "</td>" +
	    		"<td style='vertical-align: middle; font-size: 12px; padding: 5px;'><textarea  class='form-control inputPerfil' name='reactivoCompetencia[]'></textarea></td>" +
	    		"<td style='vertical-align: middle; font-size: 12px; padding: 5px;'><i class='fas fa-trash-alt borrarMeta' style='cursor: pointer;' onclick='borrarCompetencia(this);'></i></td>" +
	    		"</tr>";
	    $("#tableCompetencias tbody").append(markup);
	    $("#modalCompetencias").modal('toggle');
	}
}


//METAS   
function asignarMeta(){
	var url = "/getMetas";
	$("#divMeta").load(url, function(){
		$("#divSeleccionMeta").show();
		$("#divCreacionMeta").hide();
		$("#btnActuaDefinicionMeta").hide();
		$("#modalMetas").modal('toggle');
		$("#valNSM").val("1");
	});
}


function nuevaMeta(){
	$("#divSeleccionMeta").hide();
	$("#divCreacionMeta").show();
	$("#valNSM").val("2");
	$("#validacionNom").hide();
	$("#validacionDef").hide();
}

function seleccionarMeta(){
	$("#divSeleccionMeta").show();
	$("#divCreacionMeta").hide();
	$("#valNSM").val("1");
}

function obtenerDefinicionMeta(meta){
	$("#definicionMeta").prop('readonly', true);
	$("#btnEditDefinicionMeta").show();
	$("#btnActuaDefinicionMeta").hide();
	$.ajax({
        url: '/getDefinicionMeta',
        type: 'GET',
        data:{c:meta},
        success: function(response) {
        	$("#definicionMeta").val(response);
          }
    });
}

function borrarMeta(e){
	$(e).parents("tr").remove();
	validarPorcentaje();
}

function guardarMeta(){
	var bandera = $("#valNSM").val();
	var nombreMeta = "";
	var DefMeta = "";
	var validacion = 0;
	
	if(bandera == "1"){
		nombreMeta = $("#selectMeta option:selected").text();
		DefMeta = $("#inputDefCreacionMeta").val()
		
	} else if (bandera == "2"){
		var nom = $("#inputCreacionMeta").val();
		var def = $("#inputDefCreacionMeta").val();
		
		if(nom.length == 0 ){
			$("#validacionNom").show();
		 	validacion++;
		} else {
			$("#validacionNom").hide();
			nombreMeta = $("#inputCreacionMeta").val();
		}

		if(def.length == 0){
			$("#validacionDef").show();
			validacion++;
		} else {
			$("#validacionDef").hide();
			DefMeta = $("#inputDefCreacionMeta").val();
		}
			
	}
	
	if(validacion == 0){
		var markup = "<tr>" +
		"<td class='d-none'><input type='hidden' value='"+ bandera+"' name='banderaMeta[]'</td>" +
		"<td class='d-none'><input type='hidden' value='"+ nombreMeta+"' name='nombreMeta[]'</td>" +
		"<td class='d-none'><input type='hidden' value='"+ DefMeta+"' name='definicionMeta[]'</td>" +
		"<td style='vertical-align: middle; font-size: 12px; padding: 5px;'>" + nombreMeta + "</td>" +
		"<td style='vertical-align: middle; font-size: 12px; padding: 5px; width: 100px;'><input type='text' onkeypress='return event.charCode >= 48 && event.charCode <= 57'  onkeyup='validarPorcentaje();' name='porcentajeMeta[]' class='form-control inputPerfil'></td>" +
		"<td style='vertical-align: middle; font-size: 12px; padding: 5px; width: 30px;'><i class='fas fa-trash-alt borrarMeta' style='cursor: pointer;' onclick='borrarMeta(this);'></i></td>" +
		"</tr>";
		$("#tableMetas tbody").append(markup);
		$("#modalMetas").modal('toggle');
	}
	
}


function borrarPerfil(cod){
	if (confirm('\xbfDeseas borrar el perfil?')) {
		$.ajax({
			type: 'GET',
	        url: '/deletePerfilRecurso',
	        data:{c:cod},
	        success: function(result) {
	        	location.reload();
	          }
	    });
	} 
}

function validarSeleccionMetasCompetencias() {
	var validacion = 0;
	var totalMetasAsignadas = $("input[name='porcentajeMeta[]']").length;
	var totalCompetenciasAsignadas = $("textarea[name='reactivoCompetencia[]']").length;
	console.log(totalMetasAsignadas);
	console.log(totalCompetenciasAsignadas);
	
	if (totalMetasAsignadas == 0){
		$("#validacionSeleccionMetas").show();
		validacion++;
	} else {
		$("#validacionSeleccionMetas").hide();
	}
	
	if (totalCompetenciasAsignadas == 0){
		validacion++;
		$("#validacionSeleccionCompetencias").show();
	} else {
		$("#validacionSeleccionCompetencias").hide();
	}
	
	return validacion;

}

function validarPorcentaje(){
	var suma = 0;
	var ultimo=0;
	$("input[name='porcentajeMeta[]']").each(function() {
		ultimo = suma;
		suma += parseInt(this.value, 10);
		if(suma > 100){
			this.value = 100 - ultimo;
			suma = 100;
		}
	}); 
	
	if(Number.isNaN(suma)){
		$("#totalMetas").html("");
	}else {
		$("#totalMetas").html(suma + "%");
	}
}

function verAsignados(cod){
	var url = "verAsignados/?c="+cod;
	$("#divAsignados").load(url, function(){
		$("#modalAsignados").modal("toggle");
	});

}


function editarDefinicionMeta(){
	$("#definicionMeta").prop('readonly', false);
	$("#definicionMeta").focus();
	$("#btnEditDefinicionMeta").hide();
	$("#btnActuaDefinicionMeta").show();
}

function editarDefinicionCompetencia(){
	$("#definicionCompetencia").prop('readonly', false);
	$("#definicionCompetencia").focus();
	$("#btnEditDefinicionCompetencia").hide();
	$("#btnActuaDefinicionCompetencia").show();
}

function actualizarDefinicionMeta(){
	var cM = $("#selectMeta").val();
	var dM = $("#definicionMeta").val();
	$.ajax({
		type: 'GET',
        url: '/actualizarDefinicionMeta',
        data:{c:cM,
        	d:dM},
        success: function(result) {
        	$("#definicionMeta").prop('readonly', true);
        	$("#btnEditDefinicionMeta").show();
        	$("#btnActuaDefinicionMeta").hide();
          }
    });
}

function actualizarDefinicionCompetencia(){
	var cC = $("#selectCompetencia").val();
	var dC = $("#definicionCompetencia").val();
	$.ajax({
		type: 'GET',
        url: '/actualizarDefinicionCompetencia',
        data:{c:cC,
        	d:dC},
        success: function(result) {
        	$("#definicionCompetencia").prop('readonly', true);
        	$("#btnEditDefinicionCompetencia").show();
        	$("#btnActuaDefinicionCompetencia").hide();
          }
    });
}

$( "#sortable" ).sortable({
    stop: function( event, ui ) {
    	ordenCards();
    }
});

function ordenCards(){
	var ordenCard = [];
	$(".card").each(function() {
		ordenCard.push($(this).attr('id'));
	}); 
	$.ajax({
        url: '/actualizaOrdenCard',
        type: 'GET',
        data: { listaCards: ordenCard} ,
        contentType: 'application/json; charset=utf-8'
    }); 
}

