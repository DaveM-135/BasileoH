package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "HIST_DETALLE_RESPUESTAS_CLIMA")
public class HistoricoRespuestaClima implements  Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Long id;
	
	@Column(name = "id_recurso")
	private Long idRecurso;
	
	@Column(name = "id_pregunta_clima")
	private Long iPreguntaClima;
	
	@Column(name = "id_pregunta_respuesta")
	private Long iPreguntaRespuesta;
	
	@Column(name = "fec_respuesta")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRespuesta;
	
	@Column(name = "id_dia")
	private Long idDia;
	
	@Column(name = "val_conteo_respuesta")
	private Long valConteoRespuesta;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getIdRecurso() {
		return idRecurso;
	}

	public void setIdRecurso(Long idRecurso) {
		this.idRecurso = idRecurso;
	}

	public Long getiPreguntaClima() {
		return iPreguntaClima;
	}

	public void setiPreguntaClima(Long iPreguntaClima) {
		this.iPreguntaClima = iPreguntaClima;
	}

	public Long getiPreguntaRespuesta() {
		return iPreguntaRespuesta;
	}

	public void setiPreguntaRespuesta(Long iPreguntaRespuesta) {
		this.iPreguntaRespuesta = iPreguntaRespuesta;
	}

	public Date getFecRespuesta() {
		return fecRespuesta;
	}

	public void setFecRespuesta(Date fecRespuesta) {
		this.fecRespuesta = fecRespuesta;
	}

	public Long getIdDia() {
		return idDia;
	}

	public void setIdDia(Long idDia) {
		this.idDia = idDia;
	}

	public Long getValConteoRespuesta() {
		return valConteoRespuesta;
	}

	public void setValConteoRespuesta(Long valConteoRespuesta) {
		this.valConteoRespuesta = valConteoRespuesta;
	}
	

}
