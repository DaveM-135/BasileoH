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
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Range;
import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "CONTACTO")
public class Agenda implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_contacto")
	private Long codContacto;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_contacto")
	private String descContacto;
	
	@Column(name = "desc_puesto")
	private String descPuesto;
	
	@Range(min = 0, max=150, message = "No puedes capturar más número de recursos a cargo")
	@Column(name = "val_recursos_a_cargo")
	private Long valRecursosACargo;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Email(message = "No es un email correcto")
	@Column(name = "desc_correo_electronico")
	private String descCorreoElectronico;
	
	@Column(name = "fec_nacimiento")
	private String fecNacimiento;
	
	@Column(name = "desc_tel_celular")
	private String descTelCelular;
	
	@Column(name = "desc_tel_empresa")
	private String descTelEmpresa;
	
	@Column(name = "desc_tel_ext")
	private String descTelExt;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;
	
	@Transient
	private String nombreCliente;
	
	@Column(name = "cod_cliente")
	private Long codCliente;

	@Transient
	private String nombreCargo;
	
	@Transient
	private boolean esBorrable;
	
	@Column(name = "cod_cargo")
	private Long codCargo;
	
	@Column(name = "val_activo")
	private Long valActivo;
	
	@OneToMany(mappedBy = "agenda")
	List<DetalleProyectoContacto> detalleProyectoContacto;

	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodContacto() {
		return codContacto;
	}

	public void setCodContacto(Long codContacto) {
		this.codContacto = codContacto;
	}

	public String getDescContacto() {
		return descContacto;
	}

	public void setDescContacto(String descContacto) {
		this.descContacto = descContacto;
	}

	public String getDescPuesto() {
		return descPuesto;
	}

	public void setDescPuesto(String descPuesto) {
		this.descPuesto = descPuesto;
	}

	public Long getValRecursosACargo() {
		return valRecursosACargo;
	}

	public void setValRecursosACargo(Long valRecursosACargo) {
		this.valRecursosACargo = valRecursosACargo;
	}

	public String getDescCorreoElectronico() {
		return descCorreoElectronico;
	}

	public void setDescCorreoElectronico(String descCorreoElectronico) {
		this.descCorreoElectronico = descCorreoElectronico;
	}

	public String getFecNacimiento() {
		return fecNacimiento;
	}

	public void setFecNacimiento(String fecNacimiento) {
		this.fecNacimiento = fecNacimiento;
	}

	public String getDescTelCelular() {
		return descTelCelular;
	}

	public void setDescTelCelular(String descTelCelular) {
		this.descTelCelular = descTelCelular;
	}

	public String getDescTelEmpresa() {
		return descTelEmpresa;
	}

	public void setDescTelEmpresa(String descTelEmpresa) {
		this.descTelEmpresa = descTelEmpresa;
	}

	public String getDescTelExt() {
		return descTelExt;
	}

	public void setDescTelExt(String descTelExt) {
		this.descTelExt = descTelExt;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public Long getCodCargo() {
		return codCargo;
	}

	public void setCodCargo(Long codCargo) {
		this.codCargo = codCargo;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getNombreCliente() {
		return nombreCliente;
	}

	public void setNombreCliente(String nombreCliente) {
		this.nombreCliente = nombreCliente;
	}

	public String getNombreCargo() {
		return nombreCargo;
	}

	public void setNombreCargo(String nombreCargo) {
		this.nombreCargo = nombreCargo;
	}
	
	public List<DetalleProyectoContacto> getDetalleProyectoContacto() {
		return detalleProyectoContacto;
	}

	public void setDetalleProyectoContacto(List<DetalleProyectoContacto> detalleProyectoContacto) {
		this.detalleProyectoContacto = detalleProyectoContacto;
	}

	public Long getValActivo() {
		return valActivo;
	}

	public void setValActivo(Long valActivo) {
		this.valActivo = valActivo;
	}

	public boolean getEsBorrable() {
		return esBorrable;
	}

	public void setEsBorrable(boolean esBorrable) {
		this.esBorrable = esBorrable;
	}
	
}
