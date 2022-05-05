package com.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SpringSecurityConfig {

	@Autowired
	private JwtAuthenticationFilter authenticationFilter;

	@Bean
	public SecurityWebFilterChain configure(ServerHttpSecurity http) {
		return http.authorizeExchange().pathMatchers("/api/autenticacion/oauth/token").permitAll()

				// USUARIOS
				.pathMatchers(HttpMethod.GET, "/api/usuarios/users/existUsuario/**",
						"/api/usuarios/users/existUsername/**", "/api/usuarios/users/existEmail/**",
						"/api/usuarios/users/existCellPhone/**", "/api/usuarios/users/usuarioExisteDatos/",
						"/api/usuarios/users/existCedula/**")
				.permitAll()
				.pathMatchers(HttpMethod.GET, "/api/usuarios/users/listar/", "/api/usuarios/users/findUsername/**",
						"/api/usuarios/users/encontrarUsuario/**", "/api/usuarios/users/verUsuario/**",
						"/api/usuarios/users/verificarCodigo/**", "/api/usuarios/users/file/downloadImage/**",
						"/api/usuarios/users/obtenerEdad/**","/api/usuarios/users/file/binary/**")
				.hasAnyRole("ADMIN", "USER", "MODERATOR", "INTERVENTOR")
				.pathMatchers(HttpMethod.GET, "/api/usuarios/users/verRoleUsuario/**")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.pathMatchers(HttpMethod.PUT, "/api/usuarios/users/enviarCodigo/**", "/api/usuarios/users/editar/**",
						"/api/usuarios/users/editarUsername/**", "/api/usuarios/users/editarCellPhone/**",
						"/api/usuarios/users/editarEmail/**", "/api/usuarios/users/editarUbicacion/**",
						"/api/usuarios/users/editarContrasena/**", "/api/usuarios/users/file/uploadImage/**")
				.hasAnyRole("ADMIN", "USER", "MODERATOR", "INTERVENTOR")
				.pathMatchers(HttpMethod.PUT, "/api/usuarios/users/eliminarAdmin/**", "/api/usuarios/users/eliminarPeticionAdmin/**")
				.hasAnyRole("ADMIN", "USER", "MODERATOR")
				// OJO
				.pathMatchers(HttpMethod.POST, "/api/usuarios/users/crearUsuarioMod/").permitAll()
				// ^
				.pathMatchers(HttpMethod.PUT, "/api/usuarios/users/roleModerator/**",
						"/api/usuarios/users/roleAdmin/**", "/api/usuarios/users/arreglar/")
				.hasRole("INTERVENTOR").pathMatchers(HttpMethod.DELETE, "/api/usuarios/users/eliminar/**")
				.hasRole("INTERVENTOR")

				// AUTENTICACION
				.pathMatchers(HttpMethod.POST, "/api/autenticacion/autenticacion/arreglar")
				.hasAnyRole("ADMIN", "INTERVENTOR")

				// REGISTRO
				.pathMatchers(HttpMethod.POST, "/api/registro/registro/crearNuevo/",
						"/api/registro/registro/registro/confirmar/**")
				.permitAll().pathMatchers(HttpMethod.POST, "/api/registro/registro/arreglar/")
				.hasAnyRole("ADMIN", "INTERVENTOR")

				// INTERVENTOR
				.pathMatchers(HttpMethod.GET, "/api/interventor/interventor/listarProyectos",
						"/api/interventor/interventor/listarUsuarios")
				.hasRole("INTERVENTOR")
				.pathMatchers(HttpMethod.DELETE, "/api/interventor/interventor/eliminarUsuarioDefinitivamente/",
						"/api/interventor/interventor/eliminarProyectoDefinitivamente/")
				.hasRole("INTERVENTOR")

				// PROYECTOS
				.pathMatchers(HttpMethod.GET, "/api/proyectos/proyectos/listar/",
						"/api/proyectos/proyectos/descripcion/**", "/api/proyectos/proyectos/listarByMuro/**",
						"/api/proyectos/proyectos/imagen/downloadImage/**",
						"/api/proyectos/proyectos/file/downloadFile/**", "/api/proyectos/proyectos/imagen/binary/**",
						"/api/proyectos/proyectos/file/binary/**","/api/proyectos/proyectos/imagen/ver/link/",
						"/api/proyectos/proyectos/ver/proyecto/**")
				.hasAnyRole("USER","ADMIN","MODERATOR").pathMatchers(HttpMethod.GET, "/api/proyectos/proyectos/ver/creador/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "MODERATOR")
				.pathMatchers(HttpMethod.POST, "/api/proyectos/proyectos/crear/").hasAnyRole("ADMIN", "MODERATOR")
				.pathMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/visualizaciones/**")
				.hasAnyRole("USER", "ADMIN", "MODERATOR", "INTERVENTOR")
				.pathMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/imagen/poner/**",
						"/api/proyectos/proyectos/file/poner/**", "/api/proyectos/proyectos/eliminarAdmin/**",
						"/api/proyectos/proyectos/eliminarPeticionAdmin/**",
						"/api/proyectos/proyectos/editEnabled/**", "/api/proyectos/proyectos/editEstado/**",
						"/api/proyectos/proyectos/editarProyectos/**","/api/proyectos/proyectos/imagen/poner/link/")
				.hasAnyRole("ADMIN", "MODERATOR")

				// PREGUNTAS Y RESPUESTAS
				.pathMatchers(HttpMethod.GET, "/api/preguntasrespuestas/preguntasrespuestas/preguntas/ver/**",
						"/api/preguntasrespuestas/preguntasrespuestas/pregunta/respuesta/obtener/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestas/ver/**")
				.hasAnyRole("USER")
				.pathMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/cuestionario/responder/**",
						"/api/preguntasrespuestas/preguntasrespuestas/cuestionario/usuario/abrir/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestaFinal/**")
				.hasAnyRole("ADMIN", "MODERATOR", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/preguntas/crear/**",
						"/api/preguntasrespuestas/preguntasrespuestas/preguntas/editar/**")
				.hasAnyRole("ADMIN", "MODERATOR")

				// MURO
				.pathMatchers(HttpMethod.GET, "/api/muro/muros/listar/", "/api/muro/muros/buscar/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")

				// ESTADISTICA
				.pathMatchers(HttpMethod.GET, "/api/estadistica/estadistica/usuarios/ver/estadisticas/**",
						"/api/estadistica/estadistica/likes/ver/**", "/api/estadistica/estadistica/dislikes/ver/**",
						"/api/estadistica/estadistica/visualizacion/ver/**",
						"/api/estadistica/estadistica/ver/estadisticas/**",
						"/api/estadistica/estadistica/export/excel/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")

				// SUSCRIPCIONES
				.pathMatchers(HttpMethod.GET, "/api/suscripciones/suscripciones/inscripcion/verificar/**",
						"/api/suscripciones/suscripciones/comentarios/ver/**",
						"/api/suscripciones/suscripciones/revisarLikes/**",
						"/api/suscripciones/suscripciones/comentarios/ver/**",
						"/api/suscripciones/suscripciones/comentarios/verificar/posicion/usuario/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/suscripciones/suscripciones/inscripcion/**",
						"/api/suscripciones/suscripciones/inscripcion/anular/**",
						"/api/suscripciones/suscripciones/comentarios/**",
						"/api/suscripciones/suscripciones/likes/**", "/api/suscripciones/suscripciones/comentarios/eliminar/**")
				.hasAnyRole("USER", "ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/suscripciones/suscripciones/comentarios/eliminar/todos/**")
				.hasRole("INTERVENTOR")

				// NOTIFICACIONES
				.pathMatchers(HttpMethod.GET, "/api/notificaciones/notificaciones/verNotificaciones/**", "/api/notificaciones/notificaciones/revisar/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/borrarNotificacion/**",
						"/api/notificaciones/notificaciones/cambiarNotificacion/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")

				// BUSQUEDA
				.pathMatchers(HttpMethod.GET, "/api/busqueda/busqueda/proyectos/buscar/")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")

				// RECOMENDACIONES
				.pathMatchers(HttpMethod.GET, "/api/recomendacion/recomendaciones/proyectos/ubicacion/**",
						"/api/recomendacion/recomendaciones/muro/ubicacion/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")

				// PARAMETIZACION
				.pathMatchers(HttpMethod.GET, "/api/parametrizacion/parametros/get/**").hasAnyRole("MODERATOR")
				.pathMatchers(HttpMethod.GET, "/api/parametrizacion/parametros/terminosycondiciones/obtener/").permitAll()
				.pathMatchers(HttpMethod.PUT, "/api/parametrizacion/parametros/servicios/colocarImagen/**","/api/parametrizacion/parametros/terminosycondiciones/editar/")
				.hasAnyRole("MODERATOR")
				.pathMatchers(HttpMethod.POST, "/api/parametrizacion/parametros/crear/",
						"/api/parametrizacion/parametros/servicios/crear/")
				.hasAnyRole("MODERATOR")
				
				
				// ADMIN
				.pathMatchers("/api/notificaciones/**","/api/estadistica/**","/api/registro/**", "/api/preguntasrespuestas/**").hasRole("ADMIN")

				.anyExchange().authenticated().and()
				.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION).csrf().disable().build();
	}

}
