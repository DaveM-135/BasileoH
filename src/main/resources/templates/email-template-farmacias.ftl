<!DOCTYPE html>
<html lang="es" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
    <meta charset="utf-8"> <!-- utf-8 works for most cases -->
    <meta name="viewport" content="width=device-width"> <!-- Forcing initial-scale shouldn't be necessary -->
    <meta http-equiv="X-UA-Compatible" content="IE=edge"> <!-- Use the latest (edge) version of IE rendering engine -->
    <meta name="x-apple-disable-message-reformatting">  <!-- Disable auto-scale in iOS 10 Mail entirely -->
    <title></title> <!-- The title tag shows in email notifications, like Android 4.4. -->


    <link href="https://fonts.googleapis.com/css?family=Playfair+Display:400,400i,700,700i" rel="stylesheet">

    <!-- CSS Reset : BEGIN -->
<style type="text/css">

html,
body {
    margin: 0 auto !important;
    padding: 0 !important;
    height: 100% !important;
    width: 100% !important;
    background: #f1f1f1;
}

/* What it does: Stops email clients resizing small text. */
* {
    -ms-text-size-adjust: 100%;
    -webkit-text-size-adjust: 100%;
}

/* What it does: Centers email on Android 4.4 */
div[style*="margin: 16px 0"] {
    margin: 0 !important;
}

/* What it does: Stops Outlook from adding extra spacing to tables. */
table,
td {
    mso-table-lspace: 0pt !important;
    mso-table-rspace: 0pt !important;
}

/* What it does: Fixes webkit padding issue. */
table {
    border-spacing: 0 !important;
    border-collapse: collapse !important;
    table-layout: fixed !important;
    margin: 0 auto !important;
}

/* What it does: Uses a better rendering method when resizing images in IE. */
img {
    -ms-interpolation-mode:bicubic;
}

/* What it does: Prevents Windows 10 Mail from underlining links despite inline CSS. Styles for underlined links should be inline. */
a {
    text-decoration: none;
}

/* What it does: A work-around for email clients meddling in triggered links. */
*[x-apple-data-detectors],  /* iOS */
.unstyle-auto-detected-links *,
.aBn {
    border-bottom: 0 !important;
    cursor: default !important;
    color: inherit !important;
    text-decoration: none !important;
    font-size: inherit !important;
    font-family: inherit !important;
    font-weight: inherit !important;
    line-height: inherit !important;
}

/* What it does: Prevents Gmail from displaying a download button on large, non-linked images. */
.a6S {
    display: none !important;
    opacity: 0.01 !important;
}

/* What it does: Prevents Gmail from changing the text color in conversation threads. */
.im {
    color: inherit !important;
}

/* If the above doesn't work, add a .g-img class to any image in question. */
img.g-img + div {
    display: none !important;
}

/* What it does: Removes right gutter in Gmail iOS app: https://github.com/TedGoas/Cerberus/issues/89  */
/* Create one of these media queries for each additional viewport size you'd like to fix */

/* iPhone 4, 4S, 5, 5S, 5C, and 5SE */
@media only screen and (min-device-width: 320px) and (max-device-width: 374px) {
    u ~ div .email-container {
        min-width: 320px !important;
    }
}
/* iPhone 6, 6S, 7, 8, and X */
@media only screen and (min-device-width: 375px) and (max-device-width: 413px) {
    u ~ div .email-container {
        min-width: 375px !important;
    }
}
/* iPhone 6+, 7+, and 8+ */
@media only screen and (min-device-width: 414px) {
    u ~ div .email-container {
        min-width: 414px !important;
    }
}

</style>

    <!-- CSS Reset : END -->

    <!-- Progressive Enhancements : BEGIN -->
<style>

.primary{
	background: #c02c57;
	
}
<!-- original background: #f3a333; -->
.bg_white{
	background: #ffffff;
	padding: 0px;
}
.bg_light{
	background: #fafafa;
}
.bg_black{
	background: #000000;
}
.bg_dark{
	background: rgba(0,0,0,.8);
}
.email-section{
	padding:2.5em;
}

/*BUTTON*/
.btn{
	padding: 10px 15px;
}
.btn.btn-primary{
	border-radius: 30px;
	background: #c02c57;
	color: #ffffff;
}



h1,h2,h3,h4,h5,h6{
	font-family: Arial, Helvetica, sans-serif;
	color: #ffffff;
	margin-top: 0;
}

h7{
	font-family: Arial, Helvetica, sans-serif;
	font-size: 10px;
	color: rgba(255,255,255,.4);
	margin-top: 0;
	text-align: center;
}

body{
	font-family:Arial, Helvetica, sans-serif;
	font-weight: 400;
	font-size: 15px;
	line-height: 1.8;
	color: rgba(0,0,0,.4);
}

a{
	color: #c02c57;
}

table{
}
/*LOGO*/

.logo h1{
	margin: 0;
}
.logo h1 a{
	color: #000;
	font-size: 20px;
	font-weight: 700;
	text-transform: uppercase;
	font-family:Arial, Helvetica, sans-serif;
}

/*HERO*/
.hero{
	position: relative;
}
.hero img{

}
.hero .text{
	color: rgba(255,255,255,.8);
}
.hero .text h2{
	color: #ffffff;
	font-size: 30px;
	margin-bottom: 0;
}


/*HEADING SECTION*/
.heading-section{
}
.heading-section h2{
	color: #000000;
	font-size: 28px;
	margin-top: 0;
	line-height: 1.4;
}
.heading-section .subheading{
	margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
}
.heading-section .subheading::after{
	position: absolute;
	left: 0;
	right: 0;
	bottom: -10px;
	content: '';
	width: 100%;
	height: 2px;
	background: #c02c57;
	margin: 0 auto;
}

.heading-section-white{
	color: rgba(255,255,255,.8);
}
.heading-section-white h2{
	font-size: 28px;
	font-family: 
	line-height: 1;
	padding-bottom: 0;
}
.heading-section-white h2{
	color: #ffffff;
}
.heading-section-white .subheading{
	margin-bottom: 0;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(255,255,255,.4);
}


.icon{
	text-align: center;
}
.icon img{
}


/*SERVICES*/
.text-services{
	padding: 10px 10px 0; 
	text-align: center;
}
.text-services h3{
	font-size: 20px;
}

/*BLOG*/
.text-services .meta{
	text-transform: uppercase;
	font-size: 14px;
}

/*TESTIMONY*/
.text-testimony .name{
	margin: 0;
}
.text-testimony .position{
	color: rgba(0,0,0,.3);

}


/*VIDEO*/
.img{
	width: 100%;
	height: auto;
	position: relative;
}
.img .icon{
	position: absolute;
	top: 50%;
	left: 0;
	right: 0;
	bottom: 0;
	margin-top: -25px;
}
.img .icon a{
	display: block;
	width: 60px;
	position: absolute;
	top: 0;
	left: 50%;
	margin-left: -25px;
}



/*COUNTER*/
.counter-text{
	text-align: center;
}
.counter-text .num{
	display: block;
	color: #ffffff;
	font-size: 34px;
	font-weight: 700;
}
.counter-text .name{
	display: block;
	color: rgba(255,255,255,.9);
	font-size: 13px;
}


/*FOOTER*/

.footer{
	color: rgba(255,255,255,.5);

}
.footer .heading{
	color: #ffffff;
	font-size: 20px;
}
.footer ul{
	margin: 0;
	padding: 0;
}
.footer ul li{
	list-style: none;
	margin-bottom: 10px;
}
.footer ul li a{
	color: rgba(255,255,255,1);
}


@media screen and (max-width: 500px) {

	.icon{
		text-align: left;
	}

	.text-services{
		padding-left: 0;
		padding-right: 20px;
		text-align: left;
	}

}

</style>


</head>

<body width="100%" style="margin: 0; padding: 0 !important; mso-line-height-rule: exactly; background-color: #222222;">
	<center style="width: 100%; background-color: #f1f1f1;">
    <div style="display: none; font-size: 1px;max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; mso-hide: all; font-family: sans-serif;">
      &zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;
    </div>
    <div style="max-width: 600px; margin: 0 auto;" class="email-container">
    	<!-- BEGIN BODY -->
      <table border="0" cellpadding="0" cellspacing="0" class="container"> 
        <tbody> 
          <tr>
            <td align="left" bgcolor="#ffffff" class="wrapper center" style="padding: 20px; background-color: #ffffff;"> 
              <div class="mktoImg" id="sophi_logo">
                <a href="http://www.sophitech.mx/"><img src="https://drive.google.com/uc?export=view&id=1PrbNbggW6stOReWUDTaN6mbjlTT7XSPA"  alt="Sophitech - The business intelligence experts" class="img-max-logo" style="width: 200px; border: 0; line-height: 100%; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic;"></a>
              </div>
            </td> 
            <td style="width: 100%; background-color: #ffffff;">
            
            </td>
            <td align="right" bgcolor="#ffffff" class="wrapper center" style="padding: 20px; background-color: #ffffff;"> 
              <div class="mktoImg" id="mstr_logo">
                <a href="https://www3.microstrategy.com/es"><img src="https://drive.google.com/uc?export=view&id=1K59TfK_LSAZY14xDJHmLwfmT86GstsQq" alt="MicroStrategy - Intelligence Everywhere" class="img-max-logo" style="width: 200px; border: 0; line-height: 100%; outline: none; text-decoration: none; -ms-interpolation-mode: bicubic;"></a>
              </div>
            </td> 
          </tr> 
        </tbody> 
      </table> 
      <table> 
				<tr>
          <td valign="middle" class="text-services" style="background-image: url(https://drive.google.com/uc?export=view&id=1QjHV-P8EpYt7elmGSnm-I-FhBrsiepqs
          ); background-size: cover; height: 280px;">
            <table>
            	<tr>
            		<td>
            			<div class="text" style="color: #ffffff; padding: 0 2em; text-align: center;">
            				<h2>Design Thinking con MicroStrategy</h2>
            				<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 14px;">Design is not just what it looks like</p>
                    		<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 14px;">and feels like. Design is how it</p>
                    		<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 14px;">works.</p>
            			</div>
                 		 <div class="text" style="color: #ffffff; padding: 0 3em; text-align: right;">
                    		<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px;">~Steve Jobs~</p>
            			</div>
            		</td>
            	</tr>
            </table>
          </td>
	      </tr><!-- end tr -->
	      <tr>
		      <td class="bg_white">
		        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
		          <tr>
		            <td class="bg_dark email-section" style="color: #ffffff; text-align:center; padding: 0 30px; background-color: #303030;">
		            	<div class="heading-section heading-section-white" style="color: #ffffff; text-align:center;">
		              	<p style = "font-family:Arial, Helvetica, sans-serif; style="margin-bottom: 0;
	display: inline-block;
	font-size: 13px;
	color: rgba(255,255,255,.4);">Da clic <a href="https://drive.google.com/file/d/18ik0fx8sglKFcaLsOYNPMpbX71PrC31y/preview" target="_blank" data-autoplay="true"> aqu&iacute; </a> para ver una pequeña demostración del uso de Design Thinking con MicroStrategy.</p>
                    
		            	</div>
		            </td>
		          </tr><!-- end: tr -->
		          <tr>
		            <td align="left" bgcolor="#ffffff" class="text-services" style="text-align: left; background-color: #ffffff; padding: 15px 10px; 
	text-align: center;">
		            	<div class="heading-section" style="background-color: #ffffff; text-align: center; padding: 0 30px;">
		            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">Nuestros servicios</span>
		              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">
		              		Máxima la creatividad colectiva de tu organización aplicando MicroStrategy Hyperintelligence apoyado en el desarrollo de Design thinking.
		              	</p>
                    <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);" >Para poder obtener una propuesta de producto final, son requeridos los siguientes pasos.</p>
                  </div>
		            </td>
		          </tr><!-- end: tr -->
		          <tr>
		            <td class="bg_light email-section" style="padding: 0; width: 100%;">
		            	<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
		            		<tr>
                      <td valign="middle" width="50%" style="background-color: #fafafa;">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td class="text-services" style="text-align: left; padding: 20px 30px;">
                            	<div class="heading-section" >
								            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">Empatizar</span>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Identificamos nuestros jugadores clave con necesidad puntual de información en segundos.</p>
                                <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Estos usuarios nos ayudarán en el proceso de descubrimiento y recopilación de datos clave para construir nuestras tarjetas.</p>
								            	</div>
                            </td>
                          </tr>
                        </table>
                      </td>
                      <td valign="middle" width="50%">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td>
                              <img src="https://drive.google.com/uc?export=view&id=14y1sz3IulZ9cWE16LxCtitJwllIJxzpB" alt style="width: 100%; max-width: 600px; height: 330px; margin: auto; display: block;">
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
		            	</table>
		            </td>
		          </tr><!-- end: tr -->
		          <tr>
		            <td class="bg_light email-section" style="padding: 0; width: 100%;">
		            	<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
		            		<tr>
                      <td valign="middle" width="50%">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td>
                              <img src="https://drive.google.com/uc?export=view&id=1p7OU9tPOkw59GIuwDnp1Vg3Ag7lzE6XU" alt style="width: 100%; max-width: 600px; height: 330px; margin: auto; display: block;">
                            </td>
                          </tr>
                        </table>
                      </td>
                      <td valign="middle" width="50%" style="background-color: #fafafa;">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td class="text-services" style="text-align: left; padding: 20px 30px;">
                            	<div class="heading-section" style="background-color: #fafafa;">
								            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">DEFINIR</span>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">¿Cuáles son las palabras que usamos diariamente en nuestro negocio de las que conocemos algo relacionado con nuestras necesidades de información?</p>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Es aquí donde debemos de identificar esa lista de palabras.</p>
								            	</div>
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
		            	</table>
		            </td>
		          </tr><!-- end: tr -->
		          <tr>
		            <td class="bg_light email-section" style="padding: 0; width: 100%;">
		            	<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
		            		<tr>
                      <td valign="middle" width="50%" style="background-color: #fafafa;">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td class="text-services" style="text-align: left; padding: 20px 30px;">
                            	<div class="heading-section" style="background-color: #fafafa;">
								            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">Clasificar</span>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">¿Cuáles son las cosas que desearías saber acerca de estas palabras ,información relacionada?</p>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Trabajamos con post its para aterrizar esos deseos de información.</p>
                                <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">“I wish, I knew”</p>
								            	</div>
                            </td>
                          </tr>
                        </table>
                      </td>
                      <td valign="middle" width="50%">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td>
                              <img src="https://drive.google.com/uc?export=view&id=1ki0eyEBXJnLGB77kJPpf5RWi9bjsS4wG" alt style="width: 100%; max-width: 600px; height: 330px; margin: auto; display: block;">
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
		            	</table>
		            </td>
		          </tr><!-- end: tr -->
		          <tr>
		            <td class="bg_light email-section" style="padding: 0; width: 100%;">
		            	<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
		            		<tr>
                      <td valign="middle" width="50%">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td>
                              <img src="https://drive.google.com/uc?export=view&id=1qOPDzHe5cJrag7d5f2su6y2dIsYAgcwb" alt style="width: 100%; max-width: 600px; height: 330px; margin: auto; display: block;">
                            </td>
                          </tr>
                        </table>
                      </td>
                      <td valign="middle" width="50%" style="background-color: #fafafa;">
                        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                          <tr>
                            <td class="text-services" style="text-align: left; padding: 20px 30px;">
                            	<div class="heading-section" style="background-color: #fafafa;">
								            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">Prototipar</span>
								              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">¿Qué acciones puedes tomar relacionadas a estas palabras con el objetivo de cumplir con esos deseos de información?</p>
								            	</div>
                            </td>
                          </tr>
                        </table>
                      </td>
                    </tr>
		            	</table>
		            </td>
		          </tr><!-- end: tr -->                
              <tr>
                <table>
                  <tr>
                    <td align="left" bgcolor="#ffffff" class="text-services" style="text-align: left; background-color: #ffffff; padding-top:15px;">
                      <div class="heading-section" style="background-color: #ffffff; text-align: center; padding: 10px;">
                        <span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">¿Cuál es el resultado final del workshop?</span>
                        <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Las siguientes imágenes son el resultado de la implementación de Hyperintelligence en tu negocio.</p>
                        <p><img src="https://drive.google.com/uc?export=view&id=14v0Fo7lzRck2T1h6nLVDjk4mb3U7xz5c" alt style="width: 100%; max-width: 600px; height: auto; margin: auto; display: block;"></p>
                      </div>
                    </td>
                  </tr>      
                </table>
              </tr><!-- end: tr --> 
			  <tr>
				<table>
					<tr>
			  <td align="left" bgcolor="#ffffff" class="text-services" style="text-align: left; background-color: #fafafa; padding-top:15px;">
		            	<div class="heading-section" style="background-color: #fafafa; text-align: center; padding: 0 0px;">
		            		<span class="subheading" style = "font-family:Arial, Helvetica, sans-serif; margin-bottom: 20px !important;
	display: inline-block;
	font-size: 13px;
	text-transform: uppercase;
	letter-spacing: 2px;
	color: rgba(0,0,0,.4);
	position: relative;
	border-bottom: 1px solid #c02c57; padding-bottom: 4px;">Contacto</span>
		              	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Si deseas una demostración, cuéntanos sobre un de caso de negocio y lo resolveremos con tus datos ¡TOTALMENTE GRATIS!</p>
                    <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 13px; letter-spacing: 1px; color: rgba(0,0,0,.4);">Para más información, consúltalo con Rogelio de nuestro equipo de expertos en soluciones BI dando clic <a href="mailto:rogelio.botello@sophitech.mx">aquí</a>.</p>
		            	</div>
                      </td>
					</tr>
					</table>
                   </tr><!-- end: tr -->
					   </tr><!-- end: tr -->
		    </tr><!-- end:tr -->
      <!-- 1 Column Text + Button : END -->
      </table>
      <table align="center" role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="margin: auto;">
        <tr>
        	<td valign="middle" class="bg_black footer text-services" style="padding:0px;">
        		<table>
            	<tr>
					<td align="left" bgcolor="#ffffff" class="text-services" style="text-align: left; background-color: #303030;">
                  <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                    <tr>
                      <td style="text-align: left;">
                      	<p style = "font-family:Arial, Helvetica, sans-serif; font-size: 10px; letter-spacing: 1px; color:#788078;">&copy;All Rights Reserved.</p>
                        <p style = "font-family:Arial, Helvetica, sans-serif; font-size: 10px; letter-spacing: 1px; color:#788078;">2021 Sophitech.</p>
						<i><p style = "font-family:Arial, Helvetica, sans-serif; font-size: 8px; letter-spacing: 1px; color:#788078;">*El uso de logotipos es meramente informativo e ilustrativo y se limita a propósitos de identificación.</p></i>
                      </td>
                    </tr>
                  </table>
                </td>
				</tr>
				</table>
        </tr>
      </table>
    </div>
  </center>
</body>
</html>