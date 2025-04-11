-- -----------------------------------------------------
-- Version:     2.0
-- Date:        2025-03-07 
-- Author:      Andrea Guadalupe Concha Diaz 
-- Email:       78977@alumnos.utleon.edu.mx
--              andyconch3@gmail.com
--              DDL CREACIÓN DE TABLAS
-- ------------------------------------------------------



-- Elimina la base de datos si existe
DROP DATABASE IF EXISTS cookylanda;

-- ------------------------------------------
CREATE DATABASE cookylanda;
USE cookylanda;

-- -----------------------------------------------------------------------------------------------------------------------------
CREATE TABLE usuario (
    idUsuario          INT AUTO_INCREMENT PRIMARY KEY,
    nombreCompleto     VARCHAR(255) NOT NULL,
    apePaterno         VARCHAR(255) NOT NULL,
    apeMaterno         VARCHAR(255) NOT NULL,
    usuario            VARCHAR(255) NOT NULL UNIQUE,
    contrasenia        VARCHAR(255) NOT NULL, 
    correo             VARCHAR(255) NOT NULL UNIQUE,
    rol                ENUM('Administrador', 'Cliente', 'Vendedor', 'Cocinero') NOT NULL,
    estatus            ENUM('Activo', 'Inactivo') NOT NULL DEFAULT 'Activo',
    codigoUsuario      VARCHAR(255) NULL UNIQUE -- Nadamas para cocineros, administrador,vendedor 
);
INSERT INTO usuario ( nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario ) 
VALUES ('Yolanda', 'Cuellar', 'Garcia', 'yolis', 'scrypt:32768:8:1$1EAXGl5V5uglIUq4$d173669421a745409f83afee72dae7515047e968f9d50d31d2253f43e5eda181d9389275155b60c0383fb8644c6853238f94708ee5d1bbba573c7b157f79234d', 'yolandaa@outlook.com', 'Cliente', 'Activo', 'CLI-2001'),
	   ('Andrea', 'Concha', 'Diaz', 'andycd', 'scrypt:32768:8:1$YEXLn66tKllOxUf3$30d191e463ec99ad12b3362ec15dffb61b21efb76754c06da9d5dded7549706696294d21106ed7ea76b70f636f684f371ee41523e896487584bb672452ebebcc', 'andreacd@yahoo.com', 'Vendedor', 'Activo', 'VEN-3001'), 
       ('Alejandro', 'Rocha', 'Muñoz', 'rocha2', 'scrypt:32768:8:1$KAOpihIy0iq30yoG$e740645c3b7658fb53fda60ac1ac0abe9d1d7f303b763f87e868edee4209cacf188097f6835418c943094b332c494c6c49daeb163f56915ea219ea670c54b3d7', 'arochaa@gmail.com', 'Cocinero', 'Activo', 'COC-4002'), 
       ('Ximena', 'Alvarez', 'Mena', 'ximena123', 'scrypt:32768:8:1$BhV4c0zRAKXc7Z4t$8b4b7517a5bab994eaaf6d3bb5737328bf0c052ceee6f0223d1536d71b2762c066578a9c6156bca650d775e7eaaa9a004dddbb6f37903e2ec7547e97da8e4051', 'ximena@gmail.com', 'Administrador', 'Activo', 'ADM-1002');

SELECT * FROM usuario;


-- Agregar la columna intentos_fallidos

 ALTER TABLE usuario ADD COLUMN intentos_fallidos INT DEFAULT 0;

 -- Agregar la columna bloqueado_hasta
 ALTER TABLE usuario ADD COLUMN bloqueado_hasta DATETIME DEFAULT NULL;
 
 -- Agregar la columna ultimo_cambio_contrasenia
 ALTER TABLE usuario ADD COLUMN ultimo_cambio_contrasenia DATETIME DEFAULT CURRENT_TIMESTAMP; 
 ALTER TABLE usuario ADD COLUMN ultimo_inicio_sesion DATETIME DEFAULT NULL;
 
-- --------------------------------------------andrea --------------------------------------------------------------------------------
 
 
-- Tabla de recetas
CREATE TABLE receta (
    idReceta        INT AUTO_INCREMENT PRIMARY KEY,
    nombreGalleta   VARCHAR(255) NOT NULL,
    harIng          VARCHAR(255) NOT NULL DEFAULT 'Harina', -- Nombre Harina
    cantHar         VARCHAR(150), -- Cantidad Harina
    harUdad          VARCHAR(255) NOT NULL, -- Unidad
    manIng          VARCHAR(255) NOT NULL DEFAULT 'Mantequilla', -- Nombre Mantequilla
    cantMan         VARCHAR(150), -- Cantidad Mantequilla
    manUdad          VARCHAR(255) NOT NULL, -- Unidad
    azurIng         VARCHAR(255) NOT NULL DEFAULT 'Azucar', -- Nombre de Azúcar
    cantAzur        VARCHAR(150), -- Cantidad Azúcar
    azurUdad          VARCHAR(255) NOT NULL, -- Unidad
    huvrIng         VARCHAR(255) NOT NULL DEFAULT 'Huevo', -- Nombre Huevo
    cantHuv         VARCHAR(150), -- Cantidad Huevo
    huvUdad          VARCHAR(255) NOT NULL, -- Unidad
    horIng          VARCHAR(255) NOT NULL DEFAULT 'Polvo de Hornear', -- Nombre Polvo de Hornear
    cantHor         VARCHAR(150), -- Cantidad Polvo de Hornear
    horUdad          VARCHAR(255) NOT NULL, -- Unidad
    salIng          VARCHAR(255) NOT NULL DEFAULT 'Sal', -- Nombre Sal
    cantSal         VARCHAR(150), -- Cantidad Sal
    salUdad          VARCHAR(255) NOT NULL, -- Unidad
    LechIng         VARCHAR(255) NOT NULL DEFAULT 'Leche', -- Nombre Leche
    cantLech        VARCHAR(150), -- Cantidad Leche
    lechUdad          VARCHAR(255) NOT NULL, -- Unidad
    adicional       JSON NOT NULL, -- Nombre ingrediente adicional
    cantAdicional   JSON NOT NULL, -- Cantidad ingrediente adicional
    unidad          JSON NOT NULL, -- Nombre ingrediente adicional
    procedimiento   TEXT NOT NULL,
    imagen          LONGTEXT,
    estatus         ENUM('Activo', 'Inactivo') NOT NULL DEFAULT 'Activo',
    codigoUsuario   VARCHAR(255) -- Campo que identifica quién registró la receta
);

-- ------------------------------------------------------JUAN------------------------------------------------------------------------------

-- Tabla proveedor
CREATE TABLE proveedor (
    idProveedor INT AUTO_INCREMENT PRIMARY KEY,
    nombreProveedor VARCHAR(150) NOT NULL,
    direccion VARCHAR(255),
    telefono VARCHAR(15),
    correo VARCHAR(100),
    fechaRegistro DATETIME DEFAULT CURRENT_TIMESTAMP,
    tipoVendedor ENUM('Principal', 'Secundario') NOT NULL,
    empresa VARCHAR(150) NOT NULL,
    estatus ENUM('Activo', 'Inactivo') NOT NULL DEFAULT 'Activo',
    codigoUsuario VARCHAR(255)
);

-- Tabla producto
CREATE TABLE producto (
    idProducto INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(150) NOT NULL,
    precio FLOAT NOT NULL,
    idProveedor INT NOT NULL,
    estatus ENUM('Activo', 'Inactivo') NOT NULL DEFAULT 'Activo',
    FOREIGN KEY (idProveedor) REFERENCES proveedor(idProveedor)
);

-- Tabla materia
CREATE TABLE materia (
    idProducto INT AUTO_INCREMENT PRIMARY KEY,
    nombreProducto VARCHAR(200) NOT NULL UNIQUE,
    cantidad DECIMAL(10, 3) NOT NULL,
    fechaCompra DATE NOT NULL
);

-- Tabla compra

CREATE TABLE compra (
    idCompra INT AUTO_INCREMENT PRIMARY KEY,
    fechaCompra DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    proveedor INT NOT NULL,
    total DECIMAL(10, 2) NOT NULL,
    estatus ENUM('activo', 'inactivo') NOT NULL DEFAULT 'activo',
    codigoUsuario VARCHAR(255),
    FOREIGN KEY (proveedor) REFERENCES proveedor(idProveedor)
);

-- Tabla detalleCompra
CREATE TABLE detalleCompra (
    idDetalle INT AUTO_INCREMENT PRIMARY KEY,
    idCompra INT NOT NULL,
    nombreProducto VARCHAR(200) NOT NULL,
    presentacion VARCHAR(100) NOT NULL,
    cantidad DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (idCompra) REFERENCES compra(idCompra)
);

-- Tabla stockGalletas (para CantidadGalletas y StockGalletas que parecen ser la misma)
CREATE TABLE stockGalletas (
  idStock INT AUTO_INCREMENT PRIMARY KEY,
  nombreGalleta VARCHAR(255) NOT NULL,
  cantidadPiezas INT NOT NULL DEFAULT 0,
  fechaPreparacion DATE NOT NULL,
  fechaCaducidad DATE GENERATED ALWAYS AS (fechaPreparacion + INTERVAL 14 DAY) STORED
);


-- ------------------------------------------------ROCHA -------------------------------------------------------------------------------


CREATE TABLE merma (
    idMerma INT AUTO_INCREMENT PRIMARY KEY,
    tipoMerma ENUM('Caducidad Materia Prima ', 'Caducidad Galletas', 'Quemado','Galletas rotas ','Pérdidas por manipulación') NOT NULL, -- Tipo de producto que se desperdició
    idInventario INT NULL, -- Relación con materias primas (opcional)
    cantidadMerma DECIMAL(10,2) NOT NULL, -- Cantidad desperdiciada
    fechaMerma TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    lote VARCHAR(50), -- Número de lote (si aplica)
    producto VARCHAR(200), 
    codigoUsuario VARCHAR(255), -- Quién registró la merma
    FOREIGN KEY (idInventario) REFERENCES materia(idProducto) ON DELETE SET NULL
);



-- ----------------------------------------------------------YOLANDA ----------------------------------------------------------------------------------------



-- Tabla de ventas
CREATE TABLE venta (
    idVenta         INT AUTO_INCREMENT PRIMARY KEY,
    fechaVenta      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total           DECIMAL(10,2) NOT NULL,
    codigoUsuario   VARCHAR(255) -- Identifica quién registró la venta
);

-- Tabla de galletas
CREATE TABLE galletas (
    idGalleta       INT AUTO_INCREMENT PRIMARY KEY,
    nombre          VARCHAR(255) NOT NULL, -- Nombre de la galleta
    descripcion     TEXT, -- Opcional, para detalles adicionales
    precioUnitario  DECIMAL(10,2) NOT NULL -- Precio por galleta suelta
);

-- Tabla de presentaciones (precio depende del tipo de paquete)
CREATE TABLE presentaciones (
    idPresentacion   INT AUTO_INCREMENT PRIMARY KEY,
    nombre           VARCHAR(100) NOT NULL, -- Nombre de la presentación (Ej: "Caja Chica", "Kilo")
    cantidadGalletas INT NOT NULL, -- Cantidad de galletas en la presentación
    precio           DECIMAL(10,2) NOT NULL -- Precio total de esta presentación
);


-- Tabla de detalleVenta para registrar qué se vendió
CREATE TABLE detalleVenta (
    idDetalle       INT AUTO_INCREMENT PRIMARY KEY,
    idVenta         INT NOT NULL,
    idGalleta       INT NOT NULL, -- Relación con la tabla galletas
    Presentacion  	 varchar(100), 
    cantidad        INT NOT NULL CHECK (cantidad > 0), -- Número de unidades compradas (paquetes o galletas sueltas)
    subtotal        DECIMAL(10,2) NOT NULL, -- Precio total de este detalle
    FOREIGN KEY (idVenta) REFERENCES venta(idVenta) ON DELETE CASCADE,
    FOREIGN KEY (idGalleta) REFERENCES galletas(idGalleta) ON DELETE CASCADE
);

-- Tabla de pedidos (solo para clientes)
CREATE TABLE pedido (
    idPedido          INT AUTO_INCREMENT PRIMARY KEY,
    idUsuario         INT NOT NULL, -- Cliente que hizo el pedido
    fechaApartado     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fechaDeEntrega    DATE NOT NULL, -- Fecha de entrega
    estado            ENUM('Pendiente', 'Completado', 'Cancelado') NOT NULL DEFAULT 'Pendiente',
    anticipo          DECIMAL(10,2) NOT NULL, -- Pago inicial
    totalApagar       DECIMAL(10,2) NOT NULL, -- Monto total del pedido
    FOREIGN KEY (idUsuario) REFERENCES usuario(idUsuario) ON DELETE CASCADE
);

-- Detalle de los pedidos
CREATE TABLE detallePedido (
    idDetalle          INT AUTO_INCREMENT PRIMARY KEY,
    idPedido           INT NOT NULL,
    idGalleta          INT NOT NULL, -- Relación con la tabla galletas
	Presentacion       VARCHAR(100) NOT NULL,
    cantidad           INT NOT NULL CHECK (cantidad > 0), -- Cantidad de galletas o paquetes
    restoApagar        DECIMAL(10,2) DEFAULT 0, -- Falta por pagar después del anticipo
    FOREIGN KEY (idPedido) REFERENCES pedido(idPedido) ON DELETE CASCADE,
    FOREIGN KEY (idGalleta) REFERENCES galletas(idGalleta) ON DELETE CASCADE
);

INSERT INTO galletas (nombre, precioUnitario) VALUES
('Galleta de Arándano', 12),
('Galleta de Bombón', 10),
('Galleta de Café', 11),
('Galleta de Cajeta Agrio', 13),
('Galleta de Cherry', 12),
('Galleta de Chicle', 10),
('Galleta de Chispas', 10),
('Galleta de Chokis', 12),
('Galleta Combinada', 13),
('Galleta de Corazón', 12),
('Galleta de Crema Batida', 14),
('Galleta de Delfines', 13),
('Galleta de Dulce de Leche', 12),
('Galleta de Durazno', 12),
('Galleta Estrella', 11),
('Galleta Extra Chocolate', 14),
('Galleta Flor', 10),
('Galleta de Fresa', 12),
('Galleta de Frutos Rojos', 13),
('Galleta de Limón', 11);


INSERT INTO stockGalletas (nombreGalleta, cantidadPiezas, fechaPreparacion) VALUES
('Galleta de Arándano',10000, CURDATE()),
('Galleta de Bombón', 10000, CURDATE()),
('Galleta de Café', 10000, CURDATE()),
('Galleta de Cajeta Agrio', 10000, CURDATE()),
('Galleta de Cherry', 10000, CURDATE()),
('Galleta de Chicle', 10000, CURDATE()),
('Galleta de Chispas', 10000, CURDATE()),
('Galleta de Chokis', 10000, CURDATE()),
('Galleta Combinada', 10000, CURDATE()),
('Galleta de Corazón', 10000, CURDATE()),
('Galleta de Crema Batida', 10000, CURDATE()),
('Galleta de Delfines', 10000, CURDATE()),
('Galleta de Dulce de Leche', 10000, CURDATE()),
('Galleta de Durazno', 10000, CURDATE()),
('Galleta Estrella', 10000, CURDATE()),
('Galleta Extra Chocolate', 50, CURDATE()),
('Galleta Flor', 10000, CURDATE()),
('Galleta de Fresa', 10000, CURDATE()),
('Galleta de Frutos Rojos', 10000, CURDATE()),
('Galleta de Limón', 10000, CURDATE());



select * from stockGalletas;
select * from galletas;
select * from venta;
select * from detalleVenta;
SELECT * FROM usuario;
SELECT * FROM pedido;
SELECT * FROM detallePedido;
select * from merma;
select * from materia;
SELECT * FROM detalleCompra;
select * from receta;
