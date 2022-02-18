$(document).ready(function() {

document.getElementById("file").onchange = function(e) {
  // Creamos el objeto de la clase FileReader
  let reader = new FileReader();

  // Leemos el archivo subido y se lo pasamos a nuestro fileReader
  reader.readAsDataURL(e.target.files[0]);

  // Le decimos que cuando este listo ejecute el código interno
  reader.onload = function(){
    let preview = document.getElementById('preview'),
            image = document.createElement('img');

    image.src = reader.result;
    image.style.width = "200px";
	image.style.height = "200px";

    preview.innerHTML = '';
    preview.append(image);
  };
}

verificarFecha();

});

function verificarFecha(){

	//Minimo mes anterior
	var e = new Date();
	var dia;
	var mes;
	e.setMonth(e.getMonth() - 1);
	e.setYear(e.getFullYear());
	
	if((e.getMonth()+1)<10){
		mes="0"+(e.getMonth()+1);
	}else{
		mes=(e.getMonth()+1);
	}
	
	if(e.getDate()<10){
		dia="0"+e.getDate();
	}else{
		dia=e.getDate();
	}
	
	//Maximo dia siguiente
	var d = new Date();
	var diaPosterior;
	var mesActual;
	
	if((d.getMonth()+1)<10){
		mesActual="0"+(d.getMonth()+1);
	}else{
		mesActual=(d.getMonth()+1);
	}
	
	if(d.getDate()<10){
		diaPosterior="0"+d.getDate();
	}else{
		diaPosterior=d.getDate();
	}
	
	
	document.getElementById('fechaGasto').setAttribute("min", e.getFullYear()+"-"+mes+"-"+dia);
	document.getElementById('fechaGasto').setAttribute("max", d.getFullYear()+"-"+mesActual+"-"+diaPosterior);
	
}

