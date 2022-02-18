package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_RESPUESTAS_FLASH")
public class RespuestaFlash implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_respuesta")
	private Long codRespuesta;
	
	@Column(name = "ruta_imagen")
	private String rutaImagen;

	public Long getCodRespuesta() {
		return codRespuesta;
	}

	public void setCodRespuesta(Long codRespuesta) {
		this.codRespuesta = codRespuesta;
	}

	public String getRutaImagen() {
		return rutaImagen;
	}

	public void setRutaImagen(String rutaImagen) {
		this.rutaImagen = rutaImagen;
	}
	
	
	

}
