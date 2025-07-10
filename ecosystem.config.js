// ecosystem.config.js
module.exports = {
    apps: [{
      name: 'flask-app', // The name of your app in PM2
      script: 'gunicorn', // The script to run
      args: '-w 4 -b 0.0.0.0:5000 app:app', // Arguments to pass to Gunicorn
      interpreter: 'venv/bin/python', // The path to the Python interpreter in your virtual environment
      watch: false, // Don't use PM2's watch, we rely on git push
      env: {
        NODE_ENV: 'production',
      },
    }],
  };