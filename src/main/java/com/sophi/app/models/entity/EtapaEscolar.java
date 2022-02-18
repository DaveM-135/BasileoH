package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_ETAPA_ESCOLAR")
public class EtapaEscolar implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_etapa_escolar")
	private Long codEtapaEscolar;
	
	@Column(name = "desc_etapa_escolar")
	private String descEtapaEscolar;

	public Long getCodEtapaEscolar() {
		return codEtapaEscolar;
	}

	public void setCodEtapaEscolar(Long codEtapaEscolar) {
		this.codEtapaEscolar = codEtapaEscolar;
	}

	public String getDescEtapaEscolar() {
		return descEtapaEscolar;
	}

	public void setDescEtapaEscolar(String descEtapaEscolar) {
		this.descEtapaEscolar = descEtapaEscolar;
	}
	
}
