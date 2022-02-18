$(document).ready(function() {
	  
	 
	 resetFormEscolaridad();
	 resetFormContactoEmergencia();
	 
	//funcion que oculta dtalle de enfermedades/alergias/Embarazos a partir de opciones
	 validaEnfermedadAlergias();
	 
	 //Si cambia el valor del select hace validacion para mostrar detalle de alergias
	 $("#selectAlergias").change(function() {
		 hideByAlergias(this.value);
		});
	 
	//Si cambia el valor del select hace validacion para mostrar detalle de enfermedades
	 $("#selectEnfermedades").change(function() {
		 hideByEnfermedades(this.value);
		});
	 
	 //Oculta boton de guardar inicialmente
	 $("#divBtnGuardar").hide();
	 
	 //Deshabilita todos los elementos para editar
	 $(".dg-info").attr('disabled','disabled');
	 
  });


  //funcion que resetea el formulario de escolaridad
  function resetFormEscolaridad(){
	$("#institucionAcademica").val("");
	$("#cedulaProfesional").val("");
	$("#carrera").val("");
	$("#fecInicioEscolaridad").val("");
	$("#fecFinEscolaridad").val("");
	$("#codRecursoEscolaridad").val("");
	$("#validInstitucionAcademica").hide();
	$("#validCarrera").hide();
	$("#validFecInicio").hide();
	$("#validFecFin").hide();
  }
  
  function resetFormContactoEmergencia(){
	$("#nombreContactoEmergencia").val("");
	$("#telefonoContactoEmergencia").val("");
	$("#validNombreContactoEmergencia").hide();
	$("#validTelefonoContactoEmergencia").hide();
	$("#codContactoEmergencia").val("");
	$("#esDependiente").prop( "checked", false );
  }
  
  
  function registraContactoEmergencia(){
	  var codRecurso = $("#codRecurso").val();
	  var crc = $("#codContactoEmergencia").val();
	  var nombreContacto = $("#nombreContactoEmergencia").val();
	  var telefonoContacto =  $("#telefonoContactoEmergencia").val(); 
	  var parentescoContacto = $("#parentescoContactoEmergencia").val();
	  var esDependiente = 0;
	  
	  if( $('#esDependiente').prop('checked') ) {
		  esDependiente = 1;
		} else {
			esDependiente = 0;
		}
	  
	  if(nombreContacto.length === 0){
		  $("#validNombreContactoEmergencia").show();
	  } else if (telefonoContacto.length === 0){
		  $("#validTelefonoContactoEmergencia").show();
	  } else {
		  
		  $.ajax({
			    type: "GET",
			    url: "/guardaContactoEmergencia",
			    data: {crc:crc,
			    	nc: nombreContacto, 
			    	tc: telefonoContacto,
			    	pc: parentescoContacto,
			    	ed: esDependiente,
			    	cr: codRecurso },
				success: function(result){
					var url = "/obtieneContactosEmergencia/?codRecurso="+codRecurso;
					$("#divContactoEmergencia").load(url);
					$("#nuevaContactoEmergenciaModal").modal('hide');
					resetFormContactoEmergencia();
			    }
			});	
	  }
			
  }
  
  function editarContactoEmergencia(codContactoEmergencia){ 
	  $.ajax({
		    type: "GET",
		    url: "/obtieneContactosEmergenciaUnico",
		    data: {ce: codContactoEmergencia},
			success: function(contacto){
				var crc = encodeURIComponent(contacto[0]); //codRecursoContacto
				var cn = contacto[1]; //nombre
				var ct = contacto[2]; //telefono
				var cp = encodeURIComponent(contacto[3]); //valdependiente
				var vd = encodeURIComponent(contacto[4]); //parentesco
				
				
				$("#codContactoEmergencia").val(crc);
				$("#nombreContactoEmergencia").val(cn);
				$("#telefonoContactoEmergencia").val(ct); 
				$("#parentescoContactoEmergencia").val(vd);
				if(cp === '1'){
					$("#esDependiente").prop( "checked", true );
				} else {
					$("#esDependiente").prop( "checked", false );
				}
				$("#nuevaContactoEmergenciaModal").modal('show');
		    },
	         error: function (contacto) {
	            console.log("Algún dato viene nulo");
	        }
		});
  }
  

  //funcion que registra la escolaridad
  function registraEscolaridad(){
//  	  resetFormEscolaridad();
	  var instAcademica = $("#institucionAcademica").val();
	  var gradoEscolar = $("#gradoEscolar").val();
	  var etapaEscolar = $("#etapaEscolar").val();
	  var codRecurso = $("#codRecurso").val();
	  var cedProf = $("#cedulaProfesional").val();
	  var carrera = $("#carrera").val();
	  var fecInicio = $("#fecInicioEscolaridad").val();
	  var fecFin = $("#fecFinEscolaridad").val();
	  
	  var cre = $("#codRecursoEscolaridad").val();
	  
	  
	  if(instAcademica.length === 0){
		  $("#validInstitucionAcademica").show();
	  } else if(carrera.length === 0){
		  $("#validCarrera").show();
	  } else if(fecInicio.length === 0){
		  $("#validFecInicio").show();
	  } else if(fecFin.length === 0){
		  $("#validFecFin").show();
	  } else {
		  
		  $.ajax({
			    type: "GET",
			    url: "/guardaEscolaridad",
			    data: {cre: cre,
			    	cr: codRecurso, 
			    	ia: instAcademica,
			    	ge: gradoEscolar,
			    	ee: etapaEscolar,
			    	cp: cedProf,
			    	ca:carrera,
			    	fi:fecInicio,
			    	ff: fecFin},
				success: function(result){
					var url = "/obtieneEscolaridad/?codRecurso="+codRecurso;
					$("#divEscolaridad").load(url);
					$("#nuevaEscolaridadModal").modal('hide');
					resetFormEscolaridad();
			    }
			});	
	  }
	  
  }
  
  
  function editEscolaridad(codEscolaridad){
	  $.ajax({
		    type: "GET",
		    url: "/obtieneEscolaridadUnica",
		    data: {ce: codEscolaridad},
			success: function(escolaridad){
				var cre = encodeURIComponent(escolaridad[0]); //codRecursoEscolaridad
				var ia = escolaridad[1]; //institucion
				var ca = escolaridad[2]; //carrera
				var ge = encodeURIComponent(escolaridad[3]); //gradoEscolar
				var ee = encodeURIComponent(escolaridad[4]); //etapaescolar
				var fi = escolaridad[5]; //fechainicio
				var ff = escolaridad[6]; //fechafin
				var cp = escolaridad[7]; //cedula prof
				
				
				$("#codRecursoEscolaridad").val(cre);
				$("#institucionAcademica").val(ia);
				$("#gradoEscolar").val(ge);
				$("#etapaEscolar").val(ee);
				$("#cedulaProfesional").val(cp);
				$("#carrera").val(ca);
				$("#fecInicioEscolaridad").val(fi);
				$("#fecFinEscolaridad").val(ff);
				
				$("#nuevaEscolaridadModal").modal('show');
		    }
		});	
  }
  

  //funcion que oculta dtalle de enfermedades/alergias/Embarazos a partir de opciones
  function validaEnfermedadAlergias(){
	  hideByAlergias($("#selectAlergias").val());
	  hideByEnfermedades($("#selectEnfermedades").val());
	  hideByGenero($("#selectGenero").val());
  }

  //funcion que habilita los elementos para editar informacion
  function functionEditar(){
	  $("#divBtnEditar").hide();
	  $("#divBtnGuardar").show();
	  $(".dg-edit").removeAttr('disabled');
	  $(".dg-edit").removeClass("dg-info").addClass("dg-info-edit");
  }
  
  
  //funcion que borra un registro de escolaridad
  function borrarEscolaridad(codRegEscolaridad){
	  var codRecurso = $("#codRecurso").val();
	  $.ajax({
		    type: "GET",
		    url: "/borrarEscolaridad",
		    data: {cre: codRegEscolaridad },
			success: function(result){
				var url = "/obtieneEscolaridad/?codRecurso="+codRecurso;
				$("#divEscolaridad").load(url);
		    }
		});	
  }
  
  //funcion que borra un registro de escolaridad
  function borrarContactoEmergencia(codContactoEmergencia){
	  var codRecurso = $("#codRecurso").val();
	  $.ajax({
		    type: "GET",
		    url: "/borrarContactoEmergencia",
		    data: {cre: codContactoEmergencia },
			success: function(result){
				var url = "/obtieneContactosEmergencia/?codRecurso="+codRecurso;
				$("#divContactoEmergencia").load(url);
		    }
		});	
  }
  
  
  //Envia fommulario para guardar/actualizar informacion
  function functionGuardar(){
	  
	  var $form_datos_generales = $('#formDatosGenerales');
	  $.ajax({
        method: "POST",
        url: $form_datos_generales.attr('action'),
        data: $form_datos_generales.serialize(),
        success: function(status){
            console.log(status);
        }
	  });
	  
	  var $form_datos_empresa = $('#formDatosEmpresa');
	  $.ajax({
        method: "POST",
        url: $form_datos_empresa.attr('action'),
        data: $form_datos_empresa.serialize(),
        success: function(status){
            console.log(status);
        }
	  });

	  $("#divBtnEditar").show();
	  $("#divBtnGuardar").hide();
	  $(".dg-edit").attr('disabled','disabled');
	  $(".dg-edit").removeClass("dg-info-edit").addClass("dg-info");
  }
  
  function hideByGenero(genero){
	  if(genero=="F"){
		  $("#divEmbarazos").show();
	  }else{
		  $("#divEmbarazos").hide();
	  }
  }
  
  function hideByAlergias(valor){
	  if(valor==='Si'){
		  $("#divAlergias").show();
	  }else{
		  $("#divAlergias").hide();
		  $("#descMedicosAlergias").text("");
	  }
  }
  
  function hideByEnfermedades(valor){
	  if(valor==='Si'){
		  $("#divEnfermedades").show();
	  }else{
		  $("#divEnfermedades").hide();
		  $("#descMedicosEnfermedades").text("");
	  }
  }
  
  function myFunction(campo) {
	  console.log("escribe");
	  campo.style.backgroundColor = "red";
	}