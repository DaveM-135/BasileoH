package com.sophi.app.models.entity;

public class HistRespuestaAux {
	
	private Long valRespuesta;
	private String valImagenRespuesta;
	private Long idPreguntaRespuesta;
	private Long total;
	private Long porcentaje;
	
	public HistRespuestaAux(Long idPreguntaRespuesta, Long total) {
		super();
		this.idPreguntaRespuesta = idPreguntaRespuesta;
		this.total = total;
	}
	
	public HistRespuestaAux() {
		
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
	public Long getIdPreguntaRespuesta() {
		return idPreguntaRespuesta;
	}
	public void setIdPreguntaRespuesta(Long idPreguntaRespuesta) {
		this.idPreguntaRespuesta = idPreguntaRespuesta;
	}
	public Long getTotal() {
		return total;
	}
	public void setTotal(Long total) {
		this.total = total;
	}

	public Long getPorcentaje() {
		return porcentaje;
	}

	public void setPorcentaje(Long porcentaje) {
		this.porcentaje = porcentaje;
	}
	
	

}
