import express from 'express';
import dotenv from 'dotenv';
import authRoute from './routes/auth.route.js'
import { DB_Connection } from './database/db.js';


dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());

app.get('/', (req, res) => {
    res.send('<h1>Home Page</h1>');
});

app.use('/api/auth', authRoute);



app.listen(port, async () => {
    await DB_Connection();
    console.log(`Server started at http://loacalhost:${port}`);
});
