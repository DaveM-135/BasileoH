$(document).ready(function() {
	
	verTrayectoriaProyecto($("#codRecurso").val());
	verTrayectoriaCapacitacion($("#codRecurso").val());
	verTrayectoriaNivel($("#codRecurso").val());
	
	$('#fotoEvidencia').on('change', function() {
		var fileName = $(this).val().split('\\').pop();;
		$(this).next('.custom-file-label').html(fileName);
	})

});

//INICIO TRAYECTORIA PROYECTOS
function openModalRegistrarTrayectoriaProyecto(){
	var codRecurso = $("#codRecurso").val();
	var url = "/formTrayectoriaProyecto/?codRecurso=" + codRecurso;
	$("#recursoTrayectoriaProyectoModal").load(url, function() {
		$("#registroProyectoModal").modal('show');
	});
}


function editarTrayectoriaProyecto(cod){
	var url = "/editTrayectoriaProyecto/?rtp=" + cod;
	$("#recursoTrayectoriaProyectoModal").load(url, function() {
		$("#registroProyectoModal").modal('show');
	});
}

function verTrayectoriaProyecto(codRecurso){
	var url = "/verTrayectoriaProyecto/?codRecurso=" + codRecurso;
	$("#cardTrayectoriaProyecto").load(url);
}


function enviaDatos(){
	 var $form_trayectoria_proyectos = $('#formularioTrayectoriaProyecto');
	  $.ajax({
       method: "POST",
       url: $form_trayectoria_proyectos.attr('action'),
       data: $form_trayectoria_proyectos.serialize(),
       success: function(status){
           $("#registroProyectoModal").modal('hide');
           verTrayectoriaProyecto($("#codRecurso").val());
           actualizaConocimientosPorRecurso();
       }
	  });
}

function borrarTrayectoriaProyecto(cod){
	  $.ajax({
		    type: "GET",
		    url: "/borrarTrayectoriaProyecto",
		    data: {rtp: cod },
			success: function(status){
				verTrayectoriaProyecto($("#codRecurso").val());
				 actualizaConocimientosPorRecurso();
		    }
		});	
}
//FIN TRAYECTORIA PROYECTOS


//INICIO TRAYECTORIA CAPACITACIONES
function openModalRegistrarTrayectoriaCapacitacion(){
	var codRecurso = $("#codRecurso").val();
	var url = "/formTrayectoriaCapacitacion/?codRecurso=" + codRecurso;
	$("#recursoTrayectoriaCapacitacionModal").load(url, function() {
		$("#registroCapacitacionModal").modal('show');
	});
}

function verTrayectoriaCapacitacion(codRecurso){
	var url = "/verTrayectoriaCapacitacion/?codRecurso=" + codRecurso;
	$("#cardTrayectoriaCapacitacion").load(url);
}


function submitFormCapacitacion(){
	var $form_trayectoria_capacitacion = $('#formularioTrayectoriaCapacitacion')[0];
	var data = new FormData($form_trayectoria_capacitacion);
	$("#btnAceptarCapacitacion").prop("disabled", true);
	
    $.ajax({
        type: "POST",
        enctype: 'multipart/form-data',
        url: '/formTrayectoriaCapacitacion',
        data: data,
        processData: false,
        contentType: false,
        cache: false,
        timeout: 1000000,
        success: function(data) {
            $("#btnAceptarCapacitacion").prop("disabled", false);
            $("#registroCapacitacionModal").modal('hide');
            verTrayectoriaCapacitacion($("#codRecurso").val());
        }
    });
}

function borrarTrayectoriaCapacitacion(cod){
	  $.ajax({
		    type: "GET",
		    url: "/borrarTrayectoriaCapacitacion",
		    data: {rtc: cod },
			success: function(status){
				verTrayectoriaCapacitacion($("#codRecurso").val());
		    }
		});	
}

function editarTrayectoriaCapacitacion(cod){
	var url = "/editTrayectoriaCapacitacion/?rtc=" + cod;
	$("#recursoTrayectoriaCapacitacionModal").load(url, function() {
		$("#registroCapacitacionModal").modal('show');
	});
	
}
//FIN TRAYECTORIA CAPACITACIONES

//INICIO TRAYECTORIA NIVEL
function verTrayectoriaNivel(codRecurso){
	var url = "/verTrayectoriaNivel/?codRecurso=" + codRecurso;
	$("#cardTrayectoriaNivel").load(url);
}

function formEvaluarNivel(cod){
	var url = "/evaluarTrayectoriaNivel/?rtn=" + cod;
	$("#recursoTrayectoriaNivelModal").load(url, function() {
		$("#registroEvaluarNivelModal").modal('show');
	});
}

function submitFormNivel(){
	var $form_trayectoria_nivel = $('#formularioTrayectoriaNivel')[0];
	var data = new FormData($form_trayectoria_nivel);
	
    $.ajax({
        type: "POST",
        enctype: 'multipart/form-data',
        url: '/formTrayectoriaNivel',
        data: data,
        processData: false,
        contentType: false,
        cache: false,
        timeout: 1000000,
        success: function(data) { 
            $("#registroEvaluarNivelModal").modal('hide');
            verTrayectoriaNivel($("#codRecurso").val());
        }
    });
}

function actualizaConocimientosPorRecurso(){
	var url = "/actualizaConocimientoPorRecurso/?r=" + $("#codRecurso").val();
	$("#cardTrayectoriaNivel").load(url);
};

