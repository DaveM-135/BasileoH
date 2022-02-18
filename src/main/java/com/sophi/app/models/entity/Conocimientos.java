package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_CONOCIMIENTOS")
public class Conocimientos implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_conocimiento")
	private Long codConocimiento;
	
	@Column(name = "desc_conocimiento")
	private String descConocimiento;
	
	@Column(name = "cod_tipo_conocimiento")
	private Long codTipoConocimiento;
	
	@OneToOne
	@JoinColumn(name = "cod_tipo_conocimiento", insertable=false, updatable=false)
	private TipoConocimiento tipoConocimiento;
	
	@OneToMany(mappedBy="conocimiento")
    private List<DetalleConocimientosProyecto> detalleConocimientosProyecto;

	
	public Long getCodConocimiento() {
		return codConocimiento;
	}

	public void setCodConocimiento(Long codConocimiento) {
		this.codConocimiento = codConocimiento;
	}

	public String getDescConocimiento() {
		return descConocimiento;
	}

	public void setDescConocimiento(String descConocimiento) {
		this.descConocimiento = descConocimiento;
	}

	public Long getCodTipoConocimiento() {
		return codTipoConocimiento;
	}

	public void setCodTipoConocimiento(Long codTipoConocimiento) {
		this.codTipoConocimiento = codTipoConocimiento;
	}

	public TipoConocimiento getTipoConocimiento() {
		return tipoConocimiento;
	}

	public void setTipoConocimiento(TipoConocimiento tipoConocimiento) {
		this.tipoConocimiento = tipoConocimiento;
	}
	
	

}
