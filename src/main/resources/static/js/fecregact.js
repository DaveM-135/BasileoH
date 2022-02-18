function fecregact(){
	var date = new Date();

	var day = date.getDate();
	var month = date.getMonth() + 1;
	var year = date.getFullYear();
	
	var fecha = new Object();
	
	if(month < 10){
		fecha = year.toString().concat("-0", month.toString(), "-", day.toString());
		console.log(fecha);
		console.log(`${year}-0${month}-${day}`);
	}else{
		fecha = year.toString().concat("-", month.toString(), "-", day.toString());
		console.log(fecha);
		console.log(`${year}-${month}-${day}`);
	}
	
	console.log(document.getElementById("fecreg").value);
	console.log(document.getElementById("fecact").value);
	
	if(document.getElementById("fecreg").value == null && document.getElementById("fecact").value == null){
		document.getElementById("fecreg").value = fecha;
		document.getElementById("fecact").value = null;
	}
	
	if(document.getElementById("fecreg").value != null && document.getElementById("fecact").value == null){
		document.getElementById("fecact").value = fecha;
	}
	
	if(document.getElementById("fecreg").value != null && document.getElementById("fecact").value != null){
		document.getElementById("fecact").value = fecha;
	}
}

function codigo_cliente(){
	var codigo_cliente = document.querySelectorAll("codigocliente");
	var grupo_empresarial = document.querySelectorAll("gpo_empresarial")
	var nombre_cliente = document.getElementById("Nombre").value;
	
	codigo_cliente.value = new Date().getFullYear();
	
	var resultado_codigo_cliente = nombre_cliente.concat(codigo_cliente.value);
	
	if(nombre_cliente != ""){
		document.getElementById("codigocliente").value = resultado_codigo_cliente;
		document.getElementById("gpo_empresarial").value = nombre_cliente;
	}
	
	else{
		document.getElementById("codigocliente").value = "";
		document.getElementById("gpo_empresarial").value = "";
	}
	
	console.log(resultado);
}