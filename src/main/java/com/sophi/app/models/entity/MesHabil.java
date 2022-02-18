package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_DIAS_HABILES")
public class MesHabil implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "mes_id")
	private Long codMes;
	
	@Column(name = "val_horas_habiles")
	private Long valHorasHabiles;
	
	@Column(name = "val_horas_festivos")
	private Long valHorasFestivos;

	public Long getCodMes() {
		return codMes;
	}

	public void setCodMes(Long codMes) {
		this.codMes = codMes;
	}

	public Long getValHorasHabiles() {
		return valHorasHabiles;
	}

	public void setValHorasHabiles(Long valHorasHabiles) {
		this.valHorasHabiles = valHorasHabiles;
	}

	public Long getValHorasFestivos() {
		return valHorasFestivos;
	}

	public void setValHorasFestivos(Long valHorasFestivos) {
		this.valHorasFestivos = valHorasFestivos;
	}
	

}
