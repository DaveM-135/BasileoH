$(document).ready(function() {
	
	cargaProyectos();
	
});

function cargaInfo(){
	$("#contenidoTabla").html('<div class="spinner-grow text-muted"></div>');
	var session = $("#authGetName").val();
	var codCliente = $("#filterCliente").val();
	var url = "/proyecto/" + codCliente + "/" + session;
	$("#contenidoTabla").load(url);
}

function cargaProyectos(){
	$("#proyectosFiltro").html('<div class="spinner-grow text-muted"></div>');
	var session = $("#authGetName").val();
	var url = "/proyectoFiltro/" + session;
	$("#proyectosFiltro").load(url, function(){
		cargaInfo();
	}); 
}




