package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "CAT_PERFILES_RECURSO")
public class PerfilRecurso implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_perfil")
	private Long codPerfil;
	
	@Column(name = "desc_perfil")
	private String descPerfil;
	
	@Column(name = "desc_objetivo")
	private String descObjetivo;
	
	@Column(name = "desc_funciones")
	private String descFunciones;
	
	@Column(name = "val_orden")
	private int valOrden;
	
	@OneToMany(mappedBy = "perfil")
	List<CompetenciasPerfiles> competenciasPerfiles;
	
	@OneToMany(mappedBy = "perfil")
	List<MetasPerfiles> metasPerfiles;
	
	@Transient
	private Long totalRecursosAsignados;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;

	public Long getCodPerfil() {
		return codPerfil;
	}

	public void setCodPerfil(Long codPerfil) {
		this.codPerfil = codPerfil;
	}

	public String getDescPerfil() {
		return descPerfil;
	}

	public void setDescPerfil(String descPerfil) {
		this.descPerfil = descPerfil;
	}

	public String getDescObjetivo() {
		return descObjetivo;
	}

	public void setDescObjetivo(String descObjetivo) {
		this.descObjetivo = descObjetivo;
	}

	public String getDescFunciones() {
		return descFunciones;
	}

	public void setDescFunciones(String descFunciones) {
		this.descFunciones = descFunciones;
	}

	public int getValOrden() {
		return valOrden;
	}

	public void setValOrden(int valOrden) {
		this.valOrden = valOrden;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public List<CompetenciasPerfiles> getCompetenciasPerfiles() {
		return competenciasPerfiles;
	}

	public void setCompetenciasPerfiles(List<CompetenciasPerfiles> competenciasPerfiles) {
		this.competenciasPerfiles = competenciasPerfiles;
	}

	public List<MetasPerfiles> getMetasPerfiles() {
		return metasPerfiles;
	}

	public void setMetasPerfiles(List<MetasPerfiles> metasPerfiles) {
		this.metasPerfiles = metasPerfiles;
	}

	public Long getTotalRecursosAsignados() {
		return totalRecursosAsignados;
	}

	public void setTotalRecursosAsignados(Long totalRecursosAsignados) {
		this.totalRecursosAsignados = totalRecursosAsignados;
	}
	

}
