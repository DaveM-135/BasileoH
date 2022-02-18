package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "CAT_PREGUNTA_CLIMA")
public class PreguntaClima implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_pregunta_clima")
	private Long codPreguntaClima;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_pregunta_clima")
	private String descPreguntaClima;
	
	@Column(name = "val_tipo")
	private Long valTipo;
	
	@Column(name = "val_activo")
	public boolean valActivo;

	public Long getCodPreguntaClima() {
		return codPreguntaClima;
	}
	
	public void setCodPreguntaClima(Long codPreguntaClima) {
		this.codPreguntaClima = codPreguntaClima;
	}

	public String getDescPreguntaClima() {
		return descPreguntaClima;
	}

	public void setDescPreguntaClima(String descPreguntaClima) {
		this.descPreguntaClima = descPreguntaClima;
	}

	public Long getValTipo() {
		return valTipo;
	}

	public void setValTipo(Long valTipo) {
		this.valTipo = valTipo;
	}

	public boolean isValActivo() {
		return valActivo;
	}

	public void setValActivo(boolean valActivo) {
		this.valActivo = valActivo;
	}
	
}
