'use strict';

const groups = require.main.require('./src/groups');
const winston = require.main.require('winston');
const nbbAuthController = require.main.require('./src/controllers/authentication');

const Controllers = {};

Controllers.renderAdminPage = async (req, res) => {
	const groupData = await groups.getGroupsFromSet('groups:visible:createtime', 0, -1);
	res.render('admin/plugins/session-sharing', { groups: groupData });
};

Controllers.retrieveUser = async (req, res) => {
	const main = module.parent.exports;
	const remoteId = req.query.id;

	if (!remoteId) {
		return res.status(400).json({
			error: 'no-id-supplied',
		});
	}

	try {
		const userObj = await main.getUser(remoteId);

		if (!userObj) {
			return res.sendStatus(404);
		}

		return res.status(200).json(userObj);
	} catch (error) {
		return res.status(500).json({
			error: error.message,
		});
	}
};

Controllers.authPixel = async (req, res) => {
	const main = module.parent.exports;
	const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

	if (!req.query || !req.query.token) {
		return res.status(400).json({
			error: 'no-token-provided',
		});
	}

	const { token } = req.query;

	try {
		const uid = await main.process(token);
		await nbbAuthController.doLogin(req, uid);
		winston.verbose(`[px-session-sharing] logged in ${uid}`);

		return res.status(200)
			.cookie(main.settings.cookieName, token, {
				maxAge: 1000 * 60 * 60, // would expire after 60 minutes
				httpOnly: true, // The cookie only accessible by the web server
				path: '/', // The cookie is available in all routes
				// domain: 'nbb.catalyst.molecule.local', // main.settings.cookieDomain,
				sameSite: 'Lax',
				secure: true,
			})
			.setHeader('Content-Type', 'image/png')
			.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
			.send(pixel);
	} catch (error) {
		return res.status(500).json({
			error: error.message,
		});
	}
};

Controllers.jwtAuth = async (req, res) => {
	const main = module.parent.exports;

	if (!req.query || !req.query.token) {
		return res.status(400).json({
			error: 'no-token-provided',
		});
	}

	const returnTo = req.query.returnTo || '/';

	const { token } = req.query;

	try {
		const uid = await main.process(token);
		await nbbAuthController.doLogin(req, uid);
		winston.verbose(`[session-sharing] processed... ${uid}`);

		// we *could* consider setting the shared cookie here.
		// but the session has been created already, so it's not necessary.

		// .cookie(main.settings.cookieName, token, {
		// 	maxAge: 1000 * 60 * 60, // would expire after 60 minutes
		// 	httpOnly: true, // The cookie only accessible by the web server
		// 	path: '/', // The cookie is available in all routes
		// 	// domain: main.settings.cookieDomain,
		// 	sameSite: 'Lax',
		// 	secure: true,
		// });
		return res.status(200).send(`<html><head><meta http-equiv="Refresh" content="2; url='${returnTo}'" /></head><body><a href="${returnTo}">forwarding...</a></body></html>`);
		// ^ seems to work better than:
		// return res.redirect(302, returnTo);
	} catch (error) {
		return res.status(500).json({
			error: error.message,
		});
	}
};

Controllers.process = async (req, res) => {
	const main = module.parent.exports;

	if (!req.body || !req.body.token) {
		return res.status(400).json({
			error: 'no-token-provided',
		});
	}

	try {
		const uid = await main.process(req.body.token);

		return res.status(200).json({
			uid,
		});
	} catch (error) {
		return res.status(500).json({
			error: error.message,
		});
	}
};

Controllers.getChatRoomByGroup = async (req, res) => {
	const main = module.parent.exports;
	const slug = req.params.slug;
	const room = await main.getChatroomForGroup(slug);
	return res.status(200).json({
		status: {
			code: 'ok',
			message: 'OK',
		},
		response: room,
	});
};

module.exports = Controllers;
