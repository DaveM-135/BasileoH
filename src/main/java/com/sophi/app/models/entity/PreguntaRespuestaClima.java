package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_PREGUNTA_RESPUESTA_CLIMA")
public class PreguntaRespuestaClima implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_pregunta_respuesta")
	private Long codPreguntaRespuestaClima;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_pregunta_clima")
	private PreguntaClima preguntaClima;
	
	@Column(name = "val_respuesta")
	private Long valRespuesta;
	
	@Column(name = "val_imagen_respuesta")
	private String valImagenRespuesta;

	public Long getCodPreguntaRespuestaClima() {
		return codPreguntaRespuestaClima;
	}

	public void setCodPreguntaRespuestaClima(Long codPreguntaRespuestaClima) {
		this.codPreguntaRespuestaClima = codPreguntaRespuestaClima;
	}

	public PreguntaClima getPreguntaClima() {
		return preguntaClima;
	}

	public void setPreguntaClima(PreguntaClima preguntaClima) {
		this.preguntaClima = preguntaClima;
	}

	public Long getValRespuesta() {
		return valRespuesta;
	}

	public void setValRespuesta(Long valRespuesta) {
		this.valRespuesta = valRespuesta;
	}

	public String getValImagenRespuesta() {
		return valImagenRespuesta;
	}

	public void setValImagenRespuesta(String valImagenRespuesta) {
		this.valImagenRespuesta = valImagenRespuesta;
	}
	
}
