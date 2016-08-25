# -*- coding: utf-8 -*-
{   'active': False,
    'author': u'Daniel Santibañez Polanco, Chilean Localization Team 9.0',
    'website': 'http://globalresponse.cl',
    'category': 'Account/invoice',
    'demo_xml': [],
    'depends': [
        'account',
        'account_accountant',
        'l10n_cl_invoice',
        'l10n_cl_base_rut',
        'l10n_cl_partner_activities'
        ],
    'description': u'''
\n\nMódulo de Facturación de la localización Chilena.\n\n\nIncluye:\n
- Configuraci\xc3\xb3n de libros, diarios (journals) y otros detalles para facturación para Chile.\n
- Asistente para configurar los talonarios de facturas, boletas, guías de despacho, etc.
''',
    'init_xml': [],
    'installable': True,
    'license': 'AGPL-3',
    'name': u'Chile - Sistema de apoyo a la facturación',
    'test': [],
    'data': [
        'views/libro_compra_venta.xml',
        'wizard/build_and_send_moves.xml',
        'security/ir.model.access.csv',
        ],
    'version': '9.0.1.1',
}
